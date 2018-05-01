{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}

module Security.AccessTokenProvider.Internal.Providers.SimpleFixed
  ( probeProviderSimpleFixed
  ) where

import           Control.Exception.Safe
import           Control.Monad.IO.Class
import           Data.Format

import           Security.AccessTokenProvider.Internal.Types
import qualified Security.AccessTokenProvider.Internal.Types.Severity as Severity

-- | Access Token Provider prober for access token retrieval from the
-- @TOKEN@ environment retrieval.
probeProviderSimpleFixed :: (MonadIO m, MonadCatch m) => AtpProbe m
probeProviderSimpleFixed = AtpProbe probeProvider

probeProvider
  :: (MonadIO m, MonadThrow m)
  => Backend m
  -> AccessTokenName
  -> m (Maybe (AccessTokenProvider m t))
probeProvider backend tokenName = do
  let BackendLog { .. } = backendLog backend
  let BackendEnv { .. } = backendEnv backend
  logAddNamespace "probe-simple-fixed" $ do
    fmap AccessToken <$> envLookup "TOKEN" >>= \ case
      Just accessToken -> do
        logMsg Severity.Info [fmt|Trying access token provider 'simple-fixed'|]
        tryCreateProvider backend tokenName accessToken
      Nothing ->
        pure Nothing

tryCreateProvider
  :: Monad m
  => Backend m
  -> AccessTokenName
  -> AccessToken t
  -> m (Maybe (AccessTokenProvider m t))
tryCreateProvider backend _accessTokenName accessToken = do
  let BackendLog { .. } = backendLog backend
  logMsg Severity.Info [fmt|AccessTokenProvider started|]
  pure . Just $ AccessTokenProvider
    { retrieveAccessToken = pure accessToken
    , releaseProvider     = pure ()
    }
