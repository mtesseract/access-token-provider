{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}

module Security.AccessTokenProvider.Internal.Providers.File
  ( providerProbeFile
  ) where

import           Control.Applicative
import           Control.Exception.Safe
import           Control.Lens
import           Control.Monad.IO.Unlift
import           Data.Format
import           Data.List.NonEmpty                                     (NonEmpty (..))
import qualified Data.Map                                               as Map
import           Data.Maybe
import qualified Data.Text                                              as Text
import qualified Data.Text.Encoding                                     as Text
import           UnliftIO.STM

import qualified Security.AccessTokenProvider.Internal.Lenses           as L
import           Security.AccessTokenProvider.Internal.Providers.Common
import           Security.AccessTokenProvider.Internal.Types
import qualified Security.AccessTokenProvider.Internal.Types.Severity   as Severity

providerProbeFile
  :: ( MonadCatch m
     , MonadUnliftIO m )
  => Backend m
  -> AccessTokenName
  -> m (Maybe (AccessTokenProvider m t))
providerProbeFile backend tokenName = do
  let BackendLog { .. } = backendLog backend
  logAddNamespace "probe-file" $
    tryNewProvider tokenName makeConf pure (createFilePathTokenProvider backend)

  where makeConf = do
          let envBackend = backendEnv backend
          maybeTokenFile <- fmap Text.unpack <$> envLookup envBackend  "TOKEN_FILE"
          case maybeTokenFile of
            Just tokenFile ->
              pure . Just $ AtpConfFile { _tokens = Just Map.empty
                                        , _token  = Just tokenFile }
            Nothing ->
              tryEnvDeserialization backend ("file" :| [])

createFilePathTokenProvider
  :: ( MonadUnliftIO m
     , MonadCatch m )
  => Backend m
  -> AccessTokenName
  -> AtpConfFile
  -> m (Maybe (AccessTokenProvider m t))
createFilePathTokenProvider backend (AccessTokenName tokenName) conf = do
  let BackendLog { .. } = backendLog backend
      tokenFileMap = fromMaybe Map.empty (conf ^. L.tokens)
      maybeTokenFile = Map.lookup tokenName tokenFileMap <|> (conf^.L.token)

  case maybeTokenFile of
    Just filename -> do
      logMsg Severity.Info [fmt|AccessTokenProvider starting|]
      provider <- newProvider filename
      pure (Just provider)
    Nothing ->
      pure Nothing

  where newProvider filename = do
          readAction <- newReadAction backend filename
          pure AccessTokenProvider { retrieveAccessToken = readAction
                                   , releaseProvider     = pure () }

newReadAction
  :: ( MonadUnliftIO m
     , MonadCatch m )
  => Backend m
  -> FilePath
  -> m (m (AccessToken t))
newReadAction backend filename = do
  let fsBackend = backendFilesystem backend
      BackendLog { .. } = backendLog backend
  cache <- atomically $ newTVar (Left (toException AccessTokenProviderTokenMissing))
  pure $
    tryAny (fileRead fsBackend filename) >>= \ case
      Right bytes -> do
        liftIO . atomically $ writeTVar cache (Right bytes)
        pure (AccessToken (Text.decodeUtf8 bytes))
      Left exn -> do
        logMsg Severity.Error [fmt|Failed to read token file '${filename}': $exn|]
        liftIO (atomically (readTVar cache)) >>= \ case
          Right bytes -> do
            logMsg Severity.Warning [fmt|Using cached token from '${filename}'|]
            pure (AccessToken (Text.decodeUtf8 bytes))
          Left _exn ->
            throwM exn -- Return newer exception.
