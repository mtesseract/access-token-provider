{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}

module Security.AccessTokenProvider.Internal.Providers.Fixed
  ( providerProbeFixed
  ) where

import           Control.Applicative
import           Control.Exception.Safe
import           Control.Lens
import           Control.Monad.IO.Class
import           Data.Format
import           Data.List.NonEmpty                                     (NonEmpty (..))
import qualified Data.Map                                               as Map
import           Data.Maybe

import qualified Security.AccessTokenProvider.Internal.Lenses           as L
import           Security.AccessTokenProvider.Internal.Providers.Common
import           Security.AccessTokenProvider.Internal.Types
import qualified Security.AccessTokenProvider.Internal.Types.Severity   as Severity

providerProbeFixed
  :: (MonadIO m, MonadThrow m)
  => Backend m
  -> AccessTokenName
  -> m (Maybe (AccessTokenProvider m t))
providerProbeFixed backend tokenName = do
  let BackendLog { .. } = backendLog backend
  logAddNamespace "probe-fixed" $
    tryNewProvider tokenName makeEnvConf pure (createEnvTokenProvider backend)

  where makeEnvConf = do
          let envBackend = backendEnv backend
          maybeToken <- envLookup envBackend  "TOKEN"
          case maybeToken of
            Just token -> pure . Just $ AtpConfFixed { _tokens = Just Map.empty
                                                     , _token = Just token }
            Nothing -> tryEnvDeserialization backend ("fixed" :| [])

createEnvTokenProvider
  :: Monad m
  => Backend m
  -> AccessTokenName
  -> AtpConfFixed
  -> m (Maybe (AccessTokenProvider m t))
createEnvTokenProvider backend (AccessTokenName tokenName) conf =
  let BackendLog { .. } = backendLog backend
      tokensMap  = fromMaybe Map.empty (conf^.L.tokens)
      maybeToken = (conf^.L.token) <|> Map.lookup tokenName tokensMap
  in case maybeToken of
       Just token -> do
         logMsg Severity.Info [fmt|AccessTokenProvider started|]
         pure . Just $ AccessTokenProvider
           { retrieveAccessToken = pure (AccessToken token)
           , releaseProvider = pure ()
           }
       Nothing ->
         pure Nothing
