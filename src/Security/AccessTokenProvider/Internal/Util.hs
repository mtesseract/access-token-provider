{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}

module Security.AccessTokenProvider.Internal.Util
  ( throwDecode
  , tshow
  , parseEndpoint
  , throwDecodeValue
  ) where

import           Control.Exception.Safe
import           Control.Monad.IO.Class
import           Data.Aeson
import           Data.ByteString                             (ByteString)
import qualified Data.ByteString.Lazy                        as ByteString.Lazy
import           Data.Format
import           Data.Text                                   (Text)
import qualified Data.Text                                   as Text
import           Katip
import           Network.HTTP.Client

import           Security.AccessTokenProvider.Internal.Types

throwDecode :: (MonadThrow m, FromJSON a) => ByteString -> m a
throwDecode bytes =
  case eitherDecode (ByteString.Lazy.fromStrict bytes) of
    Right a     ->
      pure a
    Left errMsg ->
      throwM $ AccessTokenProviderDeserialization (Text.pack errMsg)

throwDecodeValue :: (MonadThrow m, FromJSON a) => Value -> m a
throwDecodeValue val =
  case fromJSON val of
    Success a ->
      pure a
    Error errMsg ->
      throwM $ AccessTokenProviderDeserialization (Text.pack errMsg)

parseEndpoint
  :: (KatipContext m, MonadIO m, MonadCatch m)
  => Text
  -> Text
  -> m Request
parseEndpoint label endpoint =
  parseRequest (Text.unpack endpoint) `catchAny` \ exn -> do
    logFM ErrorS (ls [fmt|Failed to parse $label endpoint '${endpoint}': $exn|])
    throwM exn

tshow
  :: Show a
  => a
  -> Text
tshow = Text.pack . show
