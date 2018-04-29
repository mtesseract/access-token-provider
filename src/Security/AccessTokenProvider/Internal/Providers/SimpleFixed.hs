{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}

module Security.AccessTokenProvider.Internal.Providers.SimpleFixed
  ( providerProbeSimpleFixed
  ) where

import           Control.Exception.Safe
import           Control.Monad.IO.Class
import           Data.Format

import           Security.AccessTokenProvider.Internal.Providers.Common
import           Security.AccessTokenProvider.Internal.Types
import qualified Security.AccessTokenProvider.Internal.Types.Severity   as Severity

providerProbeSimpleFixed
  :: (MonadIO m, MonadThrow m)
  => Backend m
  -> AccessTokenName
  -> m (Maybe (AccessTokenProvider m t))
providerProbeSimpleFixed backend tokenName = do
  let BackendLog { .. } = backendLog backend
  logAddNamespace "probe-simple-fixed" $
    tryNewProvider tokenName makeEnvConf pure (createEnvTokenProvider backend)

  where makeEnvConf = do
          let BackendEnv { .. } = backendEnv backend
          fmap AccessToken <$> envLookup "TOKEN"

createEnvTokenProvider
  :: Monad m
  => Backend m
  -> AccessTokenName
  -> AccessToken t
  -> m (Maybe (AccessTokenProvider m t))
createEnvTokenProvider backend _accessTokenName accessToken = do
  let BackendLog { .. } = backendLog backend
  logMsg Severity.Info [fmt|AccessTokenProvider started|]
  pure . Just $ AccessTokenProvider
    { retrieveAccessToken = pure accessToken
    , releaseProvider = pure ()
    }
