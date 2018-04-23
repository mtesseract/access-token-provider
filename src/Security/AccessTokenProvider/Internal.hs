{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE PolyKinds             #-}
{-# LANGUAGE Rank2Types            #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}

module Security.AccessTokenProvider.Internal where

import           Control.Exception.Safe
import           Control.Monad.IO.Unlift
import           Data.List.NonEmpty                                           (NonEmpty (..))
import qualified Data.List.NonEmpty                                           as NonEmpty
import           Katip

import           Security.AccessTokenProvider.Internal.Providers.File
import           Security.AccessTokenProvider.Internal.Providers.Fixed
import           Security.AccessTokenProvider.Internal.Providers.OAuth2.Ropcg
import           Security.AccessTokenProvider.Internal.Types

namespace :: Namespace
namespace = "access-token-provider"

newWithProviders
  :: (MonadThrow m, KatipContext m)
  => NonEmpty (AtpProbe m)
  -> AccessTokenName
  -> m (AccessTokenProvider m t)
newWithProviders providers tokenName = katipAddNamespace namespace $
  probeProviders (NonEmpty.toList providers)

  where probeProviders [] =
          throwM $ AccessTokenProviderMissing tokenName
        probeProviders (AtpProbe tryProvider : rest) = do
          maybeProvider <- tryProvider tokenName
          case maybeProvider of
            Nothing ->
              probeProviders rest
            Just provider ->
              pure provider

new
  :: ( KatipContext m
     , MonadUnliftIO m
     , MonadMask m
     , MonadEnvironment m
     , MonadFilesystem m
     , MonadHttp m)
  => AccessTokenName -> m (AccessTokenProvider m t)
new = newWithProviders providers

  where providers =
          AtpProbe providerProbeFixed
          :| [ AtpProbe providerProbeFile
             , AtpProbe providerProbeRopcg ]
