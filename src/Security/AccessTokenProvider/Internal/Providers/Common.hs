{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE QuasiQuotes         #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Security.AccessTokenProvider.Internal.Providers.Common
  ( tryNewProvider
  , tryEnvDeserialization
  ) where

import           Control.Exception.Safe
import           Control.Lens
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Class
import           Control.Monad.Trans.Maybe
import           Data.Aeson
import           Data.Aeson.Lens
import           Data.Format
import           Data.List.NonEmpty                          (NonEmpty)
import qualified Data.List.NonEmpty                          as NonEmpty
import           Data.Text                                   (Text)
import qualified Data.Text.Encoding                          as Text
import           Katip

import           Security.AccessTokenProvider.Internal.Types
import           Security.AccessTokenProvider.Internal.Util

tryNewProvider
  :: (MonadIO m, MonadThrow m, KatipContext m)
  => AccessTokenName
  -> m (Maybe envConf)
  -> (envConf -> m conf)
  -> (AccessTokenName -> conf -> m (Maybe (AccessTokenProvider m t)))
  -> m (Maybe (AccessTokenProvider m t))
tryNewProvider tokenName makeEnvConf makeConf providerBuilder = do
  maybeEnvConf <- makeEnvConf
  case maybeEnvConf of
    Just envConf -> do
      conf <- makeConf envConf
      providerBuilder tokenName conf
    Nothing ->
      pure Nothing

atpConfVarName :: Text
atpConfVarName = "ATP_CONF"

tryEnvDeserialization
  :: ( MonadThrow m
     , MonadEnvironment m
     , FromJSON a
     , KatipContext m )
  => NonEmpty Text
  -> m (Maybe a)
tryEnvDeserialization providers = do
  maybeConf <- runMaybeT $ do
    envVal <- MaybeT $ environmentLookup atpConfVarName
    jsonVal :: Value <- lift $ throwDecode (Text.encodeUtf8 envVal)
    provider <- MaybeT . pure $ jsonVal ^? key "provider" . _String
    logFM DebugS (ls [fmt|ATP_CONF requests AccessTokenProvider '${provider}'|])
    if provider `elem` providers
      then do logFM InfoS (ls [fmt|Using AccessTokenProvider '${NonEmpty.head providers}'|])
              pure jsonVal
      else MaybeT (pure Nothing)
  case maybeConf of
    Just conf ->
      Just <$> throwDecodeValue conf
    Nothing ->
      pure Nothing
