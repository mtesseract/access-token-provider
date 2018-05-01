{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}

module Security.AccessTokenProvider.Internal.Providers.OAuth2.Ropcg
  ( probeProviderRopcg
  ) where

import           Control.Exception.Safe
import           Control.Lens
import           Control.Monad
import           Control.Monad.IO.Class
import           Control.Monad.IO.Unlift
import           Data.Aeson
import qualified Data.ByteString                                      as ByteString
import qualified Data.ByteString.Base64                               as B64
import           Data.Format
import qualified Data.Map                                             as Map
import           Data.Maybe
import           Data.Monoid
import qualified Data.Text                                            as Text
import qualified Data.Text.Encoding                                   as Text
import           Network.HTTP.Client
import           Network.HTTP.Client.TLS
import           Network.HTTP.Types
import qualified System.Environment                                   as Env
import           System.FilePath
import           System.Random
import           UnliftIO.Async
import           UnliftIO.Concurrent
import           UnliftIO.STM

import qualified Security.AccessTokenProvider.Internal.Lenses         as L
import           Security.AccessTokenProvider.Internal.Types
import qualified Security.AccessTokenProvider.Internal.Types.Severity as Severity
import           Security.AccessTokenProvider.Internal.Util

-- | Access Token Provider prober for access token retrieval via
-- OAuth2 Resource-Owner-Password-Credentails-Grant.
probeProviderRopcg :: (MonadMask m, MonadUnliftIO m) => AtpProbe m
probeProviderRopcg = AtpProbe probeProvider

probeProvider
  :: (MonadMask m, MonadUnliftIO m)
  => Backend m
  -> AccessTokenName
  -> m (Maybe (AccessTokenProvider m t))
probeProvider backend tokenName = do
  let BackendLog { .. } = backendLog backend
      BackendEnv { .. } = backendEnv backend
  logAddNamespace "probe-ropcg" $ do
    envLookup "ATP_CONF_ROPCG" >>= \ case
      Just confS -> do
        logMsg Severity.Info [fmt|Trying access token provider 'ropcg'|]
        throwDecode (Text.encodeUtf8 confS)
          >>= createRopcgConf
          >>= tryCreateProvider backend tokenName
      Nothing ->
        pure Nothing

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
  :: (FromJSON a, MonadCatch m)
  => Backend m
  -> FilePath
  -> m a
retrieveJson backend filename = do
  let fsBackend = backendFilesystem backend
      BackendLog { .. } = backendLog backend
  content <- fileRead fsBackend filename
  case eitherDecodeStrict content of
    Right a      -> return a
    Left  errMsgStr -> do
      let errMsg = Text.pack errMsgStr
      logMsg Severity.Error [fmt|JSON deserialization error: $errMsg|]
      throwM . AccessTokenProviderDeserialization $
        [fmt|Failed to deserialize '${filename}': $errMsg|]

-- | Retrieve credentials from credentials directory.
retrieveCredentials
  :: MonadCatch m
  => Backend m
  -> AtpConfRopcg
  -> m Credentials
retrieveCredentials backend conf = do
  let baseDir = conf^.L.credentialsDirectory
  userCred   <- retrieveJson backend
                (prefixIfRelative baseDir (conf^.L.resourceOwnerPasswordFile))
  clientCred <- retrieveJson backend
                (prefixIfRelative baseDir (conf^.L.clientPasswordFile))
  return Credentials { _user   = userCred
                     , _client = clientCred }

  where prefixIfRelative baseDir filename =
          if isAbsolute filename
          then filename
          else baseDir </> filename

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
  :: (MonadIO m, MonadCatch m)
  => AtpPreconfRopcg
  -> m AtpConfRopcg
createRopcgConf envConf = do
  authEndpoint         <- parseEndpoint (envConf^.L.authEndpoint)
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
    }

  where defaultResourceOwnerPasswordFile = "user.json"
        defaultClientPasswordFile        = "client.json"

-- | Main refreshing function.
tryRefreshToken
  :: MonadCatch m
  => Backend m
  -> AtpConfRopcg
  -> AccessTokenName
  -> AtpRopcgTokenDef
  -> m AtpRopcgResponse
tryRefreshToken backend conf tokenName tokenDef =
  logAddNamespace "refreshActionOne" $ do
  credentials <- retrieveCredentials backend conf
  let httpBackend    = backendHttp backend
      bodyParameters =
        [ ("grant_type", "password")
        , ("username",   Text.encodeUtf8 (credentials^.L.user.L.applicationUsername))
        , ("password",   Text.encodeUtf8 (credentials^.L.user.L.applicationPassword))
        , ("scope",      packScopes (tokenDef^.L.scopes)) ]
      authorization  = makeBasicAuthorizationHeader (credentials^.L.client)
      httpRequest    = (conf^.L.authEndpoint) { method = "POST"
                                              , requestHeaders = [authorization] }
                       & urlEncodedBody bodyParameters
  logMsg Severity.Debug [fmt|HTTP Request for token refreshing: ${tshow httpRequest}|]
  response <- httpRequestExecute httpBackend httpRequest
  let status = responseStatus response
      body   = responseBody response
  when (status /= ok200) $ do
    logMsg Severity.Error [fmt|Failed to refresh token: ${tshow response}|]
    throwM $ decodeOAuth2Error status body
  case eitherDecode body :: Either String AtpRopcgResponse of
    Right tokenResponse -> do
      logMsg Severity.Debug [fmt|Successfully refreshed token '${tokenName}'|]
      pure tokenResponse
    Left errMsgS -> do
      let errMsg = Text.pack errMsgS
      logMsg Severity.Error [fmt|Deserialization of token response failed: $errMsg|]
      throwM $ AccessTokenProviderDeserialization errMsg

  where packScopes = ByteString.intercalate " " . map Text.encodeUtf8

        BackendLog { .. } = backendLog backend

        decodeOAuth2Error status body =
          case decode body of
            Just problem ->
              AccessTokenProviderRefreshFailure problem
            Nothing ->
              AccessTokenProviderDeserialization $
                [fmt|Deserialization of OAuth2 error object failed; response status: ${tshow status}'|]

tokenRefreshLoop
  :: forall m t
   . (MonadCatch m, MonadIO m)
  => Backend m
  -> AtpConfRopcg
  -> AccessTokenName
  -> AtpRopcgTokenDef
  -> TMVar (Either SomeException (AccessToken t))
  -> m ()
tokenRefreshLoop backend conf tokenName tokenDef cache = forever $ do
  eitherTokenResponse <- tryAny (tryRefreshToken backend conf tokenName tokenDef)
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
          :: Either SomeException AtpRopcgResponse
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
                logMsg Severity.Error [fmt|Failed to refresh token '${tokenName}': $exn|]
                liftIO $ randomRIO (1, 10) -- Some jitter: wait 1 - 10 seconds.

        BackendLog { .. } = backendLog backend

-- | In seconds.
defaultRefreshInterval :: Double
defaultRefreshInterval = 60

-- | By default, we start refreshing tokens after 80% of the
-- "expires_in" time of a token has been elapsed.
defaultRefreshTimeFactor :: Double
defaultRefreshTimeFactor = 0.8

tryCreateProvider
  :: (MonadUnliftIO m, MonadMask m)
  => Backend m
  -> AccessTokenName
  -> AtpConfRopcg
  -> m (Maybe (AccessTokenProvider m t))
tryCreateProvider backend tokenName conf = do
  let (AccessTokenName tokenNameText) = tokenName
      BackendLog { .. } = backendLog backend
      maybeTokenDef = Map.lookup tokenNameText (conf^.L.tokens)
  case maybeTokenDef of
    Just tokenDef -> do
      logMsg Severity.Info [fmt|AccessTokenProvider starting|]
      provider <- newProvider tokenDef
      pure (Just provider)
    Nothing ->
      pure Nothing

  where newProvider tokenDef = do
          (retrieveAction, releaseAction) <- newRetrieveAction
            backend conf tokenName tokenDef
          pure AccessTokenProvider { retrieveAccessToken = retrieveAction
                                   , releaseProvider     = releaseAction }
newRetrieveAction
  :: (MonadUnliftIO m, MonadCatch m)
  => Backend m
  -> AtpConfRopcg
  -> AccessTokenName
  -> AtpRopcgTokenDef
  -> m (m (AccessToken t), m ())
newRetrieveAction backend conf tokenName tokenDef = do
  cache <- atomically newEmptyTMVar
  asyncHandle <- async $ tokenRefreshLoop backend conf tokenName tokenDef cache
  link asyncHandle
  pure $ do
    let retrieveAction = atomically (readTMVar cache) >>= \ case
          Right token -> pure token
          Left exn    -> throwM exn
        releaseAction = cancel asyncHandle
    (retrieveAction, releaseAction)
