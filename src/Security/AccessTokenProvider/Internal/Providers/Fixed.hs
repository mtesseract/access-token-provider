{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}

module Security.AccessTokenProvider.Internal.Providers.Fixed
  ( probeProviderFixed
  ) where

import           Control.Exception.Safe
import           Control.Lens
import           Control.Monad.IO.Class
import           Data.Format
import qualified Data.Map                                             as Map
import           Data.Maybe
import qualified Data.Text.Encoding                                   as Text

import qualified Security.AccessTokenProvider.Internal.Lenses         as L
import           Security.AccessTokenProvider.Internal.Types
import qualified Security.AccessTokenProvider.Internal.Types.Severity as Severity
import           Security.AccessTokenProvider.Internal.Util

-- | Access Token Provider prober for environment based access token
-- retrieval.
probeProviderFixed :: (MonadIO m, MonadCatch m) => AtpProbe m
probeProviderFixed = AtpProbe probeProvider

probeProvider
  :: (MonadIO m, MonadThrow m)
  => Backend m
  -> AccessTokenName
  -> m (Maybe (AccessTokenProvider m t))
probeProvider backend tokenName = do
  let BackendLog { .. } = backendLog backend
      BackendEnv { .. } = backendEnv backend
  logAddNamespace "probe-fixed" $ do
    envLookup "ATP_CONF_FIXED" >>= \ case
      Just confS -> do
        logMsg Severity.Info [fmt|Trying access token provider 'fixed'|]
        throwDecode (Text.encodeUtf8 confS) >>= tryCreateProvider backend tokenName
      Nothing ->
        pure Nothing

tryCreateProvider
  :: Monad m
  => Backend m
  -> AccessTokenName
  -> AtpConfFixed
  -> m (Maybe (AccessTokenProvider m t))
tryCreateProvider backend (AccessTokenName tokenName) conf =
  let BackendLog { .. } = backendLog backend
      tokensMap  = fromMaybe Map.empty (conf^.L.tokens)
  in case Map.lookup tokenName tokensMap of
       Just token -> do
         logMsg Severity.Info [fmt|AccessTokenProvider started|]
         pure . Just $ AccessTokenProvider
           { retrieveAccessToken = pure (AccessToken token)
           , releaseProvider = pure ()
           }
       Nothing ->
         pure Nothing
