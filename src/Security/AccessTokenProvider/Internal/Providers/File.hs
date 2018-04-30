{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}

module Security.AccessTokenProvider.Internal.Providers.File
  ( probeProviderFile
  ) where

import           Control.Exception.Safe
import           Control.Lens
import           Control.Monad.IO.Unlift
import           Data.Format
import qualified Data.Map                                             as Map
import           Data.Maybe
import qualified Data.Text.Encoding                                   as Text
import           UnliftIO.STM

import qualified Security.AccessTokenProvider.Internal.Lenses         as L
import           Security.AccessTokenProvider.Internal.Types
import qualified Security.AccessTokenProvider.Internal.Types.Severity as Severity
import           Security.AccessTokenProvider.Internal.Util

probeProviderFile :: (MonadUnliftIO m, MonadCatch m) => AtpProbe m
probeProviderFile = AtpProbe probeProvider

probeProvider
  :: (MonadCatch m, MonadUnliftIO m)
  => Backend m
  -> AccessTokenName
  -> m (Maybe (AccessTokenProvider m t))
probeProvider backend tokenName = do
  let BackendLog { .. } = backendLog backend
      BackendEnv { .. } = backendEnv backend
  logAddNamespace "probe-file" $ do
    envLookup "ATP_CONF_FILE" >>= \ case
      Just confS -> do
        logMsg Severity.Info [fmt|Trying access token provider 'file'|]
        throwDecode (Text.encodeUtf8 confS) >>= tryCreateProvider backend tokenName
      Nothing ->
        pure Nothing

tryCreateProvider
  :: (MonadUnliftIO m, MonadCatch m)
  => Backend m
  -> AccessTokenName
  -> AtpConfFile
  -> m (Maybe (AccessTokenProvider m t))
tryCreateProvider backend (AccessTokenName tokenName) conf = do
  let BackendLog { .. } = backendLog backend
      tokenFileMap = fromMaybe Map.empty (conf ^. L.tokens)
  case Map.lookup tokenName tokenFileMap of
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
  :: (MonadUnliftIO m, MonadCatch m)
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
