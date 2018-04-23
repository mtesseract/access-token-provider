{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Security.AccessTokenProvider.Internal.Util.Test
  ( securityAccessTokenProviderInternalUtilTest
  ) where

import           Control.Exception.Safe
import           Data.Aeson                                  (Value)
import           Test.Tasty
import           Test.Tasty.HUnit

import           Security.AccessTokenProvider.Internal.Types
import           Security.AccessTokenProvider.Internal.Util

securityAccessTokenProviderInternalUtilTest :: [TestTree]
securityAccessTokenProviderInternalUtilTest =
  [ testGroup "Security.AccessTokenProvider.Internal.Util"
    [ testCase "throwDecode throws on deserialization failure"
        throwDecodeThrowsDeserializationFailure
    , testCase "throwDecode deserializes JSON"
        throwDecodeDeserializes
    ]
  ]

throwDecodeThrowsDeserializationFailure :: Assertion
throwDecodeThrowsDeserializationFailure = do
  let bs = "[1, 2, 3}"
  Left _res :: Either AccessTokenProviderException [Int] <- try $ throwDecode bs
  pure ()

throwDecodeDeserializes :: Assertion
throwDecodeDeserializes = do
  let bs = "{\"numbers\": [1, 2, 3]}"
  _res :: Value <- throwDecode bs
  pure ()
