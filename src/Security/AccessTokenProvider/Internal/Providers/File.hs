{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
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
import           Katip
import           UnliftIO.STM

import qualified Security.AccessTokenProvider.Internal.Lenses           as L
import           Security.AccessTokenProvider.Internal.Providers.Common
import           Security.AccessTokenProvider.Internal.Types

providerProbeFile
  :: ( KatipContext m
     , MonadFilesystem m
     , MonadCatch m
     , MonadEnvironment m
     , MonadUnliftIO m )
  => AccessTokenName -> m (Maybe (AccessTokenProvider m t))
providerProbeFile tokenName = katipAddNamespace "probe-file" $
  tryNewProvider tokenName makeConf pure createFilePathTokenProvider

  where makeConf = do
          maybeTokenFile <- fmap Text.unpack <$> environmentLookup  "TOKEN_FILE"
          case maybeTokenFile of
            Just tokenFile ->
              pure . Just $ AtpConfFile { _tokens = Just Map.empty
                                        , _token  = Just tokenFile }
            Nothing ->
              tryEnvDeserialization ("file" :| [])

createFilePathTokenProvider
  :: ( KatipContext m
     , MonadFilesystem m
     , MonadUnliftIO m
     , MonadCatch m )
  => AccessTokenName
  -> AtpConfFile
  -> m (Maybe (AccessTokenProvider m t))
createFilePathTokenProvider (AccessTokenName tokenName) conf = do
  let tokenFileMap = fromMaybe Map.empty (conf ^. L.tokens)
      maybeTokenFile = Map.lookup tokenName tokenFileMap <|> (conf^.L.token)

  case maybeTokenFile of
    Just filename -> do
      logFM InfoS (ls [fmt|AccessTokenProvider starting|])
      provider <- newProvider filename
      pure (Just provider)
    Nothing ->
      pure Nothing

  where newProvider filename = do
          readAction <- newReadAction filename
          pure AccessTokenProvider { retrieveAccessToken = readAction
                                   , releaseProvider     = pure () }

newReadAction
  :: ( MonadFilesystem m
     , MonadUnliftIO m
     , MonadCatch m
     , KatipContext m )
  => FilePath
  -> m (m (AccessToken t))
newReadAction filename = do
  cache <- atomically $ newTVar (Left (toException AccessTokenProviderTokenMissing))
  pure $
    tryAny (fileRead filename) >>= \ case
      Right bytes -> do
        liftIO . atomically $ writeTVar cache (Right bytes)
        pure (AccessToken (Text.decodeUtf8 bytes))
      Left exn -> do
        logFM ErrorS (ls [fmt|Failed to read token file '${filename}': $exn|])
        liftIO (atomically (readTVar cache)) >>= \ case
          Right bytes -> do
            logFM WarningS (ls [fmt|Using cached token from '${filename}'|])
            pure (AccessToken (Text.decodeUtf8 bytes))
          Left _exn ->
            throwM exn -- Return newer exception.
