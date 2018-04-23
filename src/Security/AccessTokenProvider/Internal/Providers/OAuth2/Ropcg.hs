{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE ScopedTypeVariables   #-}

module Security.AccessTokenProvider.Internal.Providers.OAuth2.Ropcg
  ( providerProbeRopcg
  ) where

import           Control.Applicative
import           Control.Exception.Safe
import           Control.Lens
import           Control.Monad
import           Control.Monad.IO.Class
import           Control.Monad.IO.Unlift
import           Data.Aeson
import qualified Data.ByteString                                        as ByteString
import qualified Data.ByteString.Base64                                 as B64
import           Data.Format
import           Data.List.NonEmpty                                     (NonEmpty (..))
import qualified Data.Map                                               as Map
import           Data.Maybe
import           Data.Monoid
import qualified Data.Text                                              as Text
import qualified Data.Text.Encoding                                     as Text
import           Katip
import           Network.HTTP.Client
import           Network.HTTP.Client.TLS
import           Network.HTTP.Types
import qualified System.Environment                                     as Env
import           System.FilePath
import           System.Random
import           UnliftIO.Async
import           UnliftIO.Concurrent
import           UnliftIO.STM

import qualified Security.AccessTokenProvider.Internal.Lenses           as L
import           Security.AccessTokenProvider.Internal.Providers.Common
import           Security.AccessTokenProvider.Internal.Types
import           Security.AccessTokenProvider.Internal.Util

providerProbeRopcg
  :: ( MonadMask m
     , MonadUnliftIO m
     , KatipContext m
     , MonadEnvironment m
     , MonadHttp m
     , MonadFilesystem m )
  => AccessTokenName
  -> m (Maybe (AccessTokenProvider m t))
providerProbeRopcg tokenName =
  tryNewProvider tokenName mkConf createRopcgConf
    createTokenProviderResourceOwnerPasswordCredentials

  where mkConf =
          tryEnvDeserialization
          ("resource-owner-password-credentials-grant" :| ["ropcg"])

-- | Derive an authorization header from provided client credentials.
makeBasicAuthorizationHeader
  :: ClientCredentials
  -> Header
makeBasicAuthorizationHeader credentials =
  let b64Token = [credentials^.L.clientId, credentials^.L.clientSecret]
                 & map Text.encodeUtf8
                 & ByteString.intercalate ":"
                 & B64.encode
  in ("Authorization", "Basic " <> b64Token)

retrieveJson
  :: (MonadFilesystem m, KatipContext m, FromJSON a, MonadCatch m)
  => FilePath
  -> m a
retrieveJson filename = do
  content <- fileRead filename
  case eitherDecodeStrict content of
    Right a      -> return a
    Left  errMsgStr -> do
      let errMsg = Text.pack errMsgStr
      logFM ErrorS (ls [fmt|JSON deserialization error: $errMsg|])
      throwM . AccessTokenProviderDeserialization $
        [fmt|Failed to deserialize '${filename}': $errMsg|]

-- | Retrieve credentials from credentials directory.
retrieveCredentials
  :: (MonadFilesystem m, KatipContext m, MonadCatch m)
  => AtpConfRopcg
  -> m Credentials
retrieveCredentials conf = do
  let baseDir = conf^.L.credentialsDirectory
  userCred   <- retrieveJson
                (prefixIfRelative baseDir (conf^.L.resourceOwnerPasswordFile))
  clientCred <- retrieveJson
                (prefixIfRelative baseDir (conf^.L.clientPasswordFile))
  return Credentials { _user   = userCred
                     , _client = clientCred }

  where prefixIfRelative baseDir filename =
          if isAbsolute filename
          then filename
          else baseDir </> filename

maskHttpRequest
  :: Request
  -> Request
maskHttpRequest req =
  req { requestHeaders = maskHttpHeaders headers }
  where headers = requestHeaders req

        maskHttpHeaders = map maskHttpHeader

        maskHttpHeader ("Authorization", _) = ("Authorization", "XXXXXXXXXXXXXXXX")
        maskHttpHeader hdr = hdr

-- | Environment variable expected to contain the path to the mint
-- credentials.
envCredentialsDirectory :: String
envCredentialsDirectory = "CREDENTIALS_DIR"

retrieveCredentialsDir
  :: (MonadIO m, MonadThrow m)
  => AtpPreconfRopcg
  -> m FilePath
retrieveCredentialsDir envConf =
  case envConf^.L.credentialsDirectory of
    Just dir ->
      pure dir
    Nothing  ->
      liftIO (fromMaybe "." <$> Env.lookupEnv envCredentialsDirectory)

createRopcgConf
  :: (KatipContext m, MonadIO m, MonadCatch m)
  => AtpPreconfRopcg
  -> m AtpConfRopcg
createRopcgConf envConf = do
  authEndpoint         <- parseEndpoint "authentication" (envConf^.L.authEndpoint)
  credentialsDirectory <- retrieveCredentialsDir envConf
  let clientPasswordFile        = fromMaybe defaultClientPasswordFile
                                  (envConf^.L.clientPasswordFile)
  let resourceOwnerPasswordFile = fromMaybe defaultResourceOwnerPasswordFile
                                  (envConf^.L.resourceOwnerPasswordFile)
  let refreshTimeFactor         = fromMaybe defaultRefreshTimeFactor
                          (envConf^.L.refreshTimeFactor)
  manager <- liftIO $ newManager tlsManagerSettings
  pure AtpConfRopcg
    { _credentialsDirectory      = credentialsDirectory
    , _clientPasswordFile        = clientPasswordFile
    , _resourceOwnerPasswordFile = resourceOwnerPasswordFile
    , _refreshTimeFactor         = refreshTimeFactor
    , _authEndpoint              = authEndpoint
    , _manager                   = manager
    , _tokens                    = envConf^.L.tokens
    , _token                     = envConf^.L.token
    }

  where defaultResourceOwnerPasswordFile = "user.json"
        defaultClientPasswordFile = "client.json"

-- | Main refreshing function.
tryRefreshToken
  :: ( MonadCatch m
     , KatipContext m
     , MonadHttp m
     , MonadFilesystem m )
  => AtpConfRopcg
  -> AccessTokenName
  -> AtpRopcgTokenDef
  -> m AtpRopcgResponse
tryRefreshToken conf tokenName tokenDef =
  katipAddContext (sl "tokenName" tokenName) $
  katipAddNamespace "refreshActionOne" $ do
  credentials <- retrieveCredentials conf
  let manager        = conf^.L.manager
      bodyParameters =
        [ ("grant_type", "password")
        , ("username",   Text.encodeUtf8 (credentials^.L.user.L.applicationUsername))
        , ("password",   Text.encodeUtf8 (credentials^.L.user.L.applicationPassword))
        , ("scope",      packScopes (tokenDef^.L.scopes)) ]
      authorization  = makeBasicAuthorizationHeader (credentials^.L.client)
      httpRequest    = (conf^.L.authEndpoint) { method = "POST"
                                              , requestHeaders = [authorization] }
                       & urlEncodedBody bodyParameters
      maskedRequest  = Text.pack . show $ maskHttpRequest httpRequest
  logFM DebugS (ls [fmt|HTTP Request for token refreshing: $maskedRequest|])
  response <- httpRequestExecute httpRequest manager
  let status = responseStatus response
      body   = responseBody response
  when (status /= ok200) $ do
    logFM ErrorS (ls [fmt|Failed to refresh token: ${tshow response}|])
    throwM $ decodeOAuth2Error status body
  case eitherDecode body :: Either String AtpRopcgResponse of
    Right tokenResponse -> do
      logFM DebugS (ls [fmt|Successfully refreshed token '${tokenName}'|])
      pure tokenResponse
    Left errMsgS -> do
      let errMsg = Text.pack errMsgS
      logFM ErrorS (ls [fmt|Deserialization of token response failed: $errMsg|])
      throwM $ AccessTokenProviderDeserialization errMsg

  where packScopes = ByteString.intercalate " " . map Text.encodeUtf8

        decodeOAuth2Error status body =
          case decode body of
            Just problem ->
              AccessTokenProviderRefreshFailure problem
            Nothing ->
              AccessTokenProviderDeserialization $
                [fmt|Deserialization of OAuth2 error object failed; response status: ${tshow status}'|]

tokenRefreshLoop
  :: ( MonadCatch m
     , KatipContext m
     , MonadHttp m
     , MonadFilesystem m )
  => AtpConfRopcg
  -> AccessTokenName
  -> AtpRopcgTokenDef
  -> TMVar (Either SomeException (AccessToken t))
  -> m ()
tokenRefreshLoop conf tokenName tokenDef cache = forever $ do
  eitherTokenResponse <- tryAny (tryRefreshToken conf tokenName tokenDef)
  atomically $ do
    let eitherToken = AccessToken . view L.accessToken <$> eitherTokenResponse
    isEmptyTMVar cache >>= \ case
      True -> putTMVar cache eitherToken
      False -> void $ swapTMVar cache eitherToken
  secondsToWait <- computeDurationToWait eitherTokenResponse
  let microsToWait = round $ secondsToWait * 10^(6 :: Int)
  threadDelay microsToWait

  where -- Returns duration in seconds.
        computeDurationToWait
          :: KatipContext m
          => Either SomeException AtpRopcgResponse
          -> m Double
        computeDurationToWait eitherTokenResponse =
          case eitherTokenResponse of
              Right tokenResponse ->
                case tokenResponse^.L.expiresIn of
                  Just expiresIn ->
                    pure $ conf^.L.refreshTimeFactor * fromIntegral expiresIn
                  Nothing ->
                    pure defaultRefreshInterval
              Left exn -> do
                logFM ErrorS (ls [fmt|Failed to refresh token '${tokenName}': $exn|])
                liftIO $ randomRIO (1, 10) -- Some jitter: wait 1 - 10 seconds.

-- | In seconds.
defaultRefreshInterval :: Double
defaultRefreshInterval = 60

-- | By default, we start refreshing tokens after 80% of the
-- "expires_in" time of a token has been elapsed.
defaultRefreshTimeFactor :: Double
defaultRefreshTimeFactor = 0.8

createTokenProviderResourceOwnerPasswordCredentials
  :: ( MonadUnliftIO m
     , MonadMask m
     , KatipContext m
     , MonadHttp m
     , MonadFilesystem m )
  => AccessTokenName
  -> AtpConfRopcg
  -> m (Maybe (AccessTokenProvider m t))
createTokenProviderResourceOwnerPasswordCredentials tokenName conf = do
  let (AccessTokenName tokenNameText) = tokenName
      maybeTokenDef = Map.lookup tokenNameText (conf^.L.tokens)
                      <|> (conf^.L.token)

  case maybeTokenDef of
    Just tokenDef -> do
      logFM InfoS (ls [fmt|AccessTokenProvider starting|])
      provider <- newProvider tokenDef
      pure (Just provider)
    Nothing ->
      pure Nothing

  where newProvider tokenDef = do
          (retrieveAction, releaseAction) <- newRetrieveAction conf tokenName tokenDef
          pure AccessTokenProvider { retrieveAccessToken = retrieveAction
                                   , releaseProvider     = releaseAction }
newRetrieveAction
  :: ( KatipContext m
     , MonadUnliftIO m
     , MonadCatch m
     , MonadHttp m
     , MonadFilesystem m )
  => AtpConfRopcg
  -> AccessTokenName
  -> AtpRopcgTokenDef
  -> m (m (AccessToken t), m ())
newRetrieveAction conf tokenName tokenDef = do
  cache <- atomically newEmptyTMVar
  asyncHandle <- async $ tokenRefreshLoop conf tokenName tokenDef cache
  link asyncHandle
  pure $ do
    let retrieveAction = atomically (readTMVar cache) >>= \ case
          Right token -> pure token
          Left exn    -> throwM exn
        releaseAction = cancel asyncHandle
    (retrieveAction, releaseAction)
