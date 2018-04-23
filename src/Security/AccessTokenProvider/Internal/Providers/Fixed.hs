{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
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
import           Katip

import qualified Security.AccessTokenProvider.Internal.Lenses           as L
import           Security.AccessTokenProvider.Internal.Providers.Common
import           Security.AccessTokenProvider.Internal.Types

providerProbeFixed
  :: (KatipContext m, MonadIO m, MonadThrow m, MonadEnvironment m)
  => AccessTokenName
  -> m (Maybe (AccessTokenProvider m t))
providerProbeFixed tokenName = katipAddNamespace "probe-fixed" $
  tryNewProvider tokenName makeEnvConf pure createEnvTokenProvider

  where makeEnvConf = do
          maybeToken <- environmentLookup  "TOKEN"
          case maybeToken of
            Just token -> pure . Just $ AtpConfFixed { _tokens = Just Map.empty
                                                     , _token = Just token }
            Nothing -> tryEnvDeserialization ("fixed" :| [])

createEnvTokenProvider
  :: (KatipContext m, MonadEnvironment m)
  => AccessTokenName
  -> AtpConfFixed
  -> m (Maybe (AccessTokenProvider m t))
createEnvTokenProvider (AccessTokenName tokenName) conf =
  let tokensMap  = fromMaybe Map.empty (conf^.L.tokens)
      maybeToken = (conf^.L.token) <|> Map.lookup tokenName tokensMap
  in case maybeToken of
       Just token -> do
         logFM InfoS (ls [fmt|AccessTokenProvider started|])
         pure . Just $ AccessTokenProvider
           { retrieveAccessToken = pure (AccessToken token)
           , releaseProvider = pure ()
           }
       Nothing ->
         pure Nothing
