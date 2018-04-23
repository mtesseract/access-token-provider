{-# LANGUAGE OverloadedStrings #-}

module Security.AccessTokenProvider.Internal.Test
  ( securityAccessTokenProviderInternalTest
  ) where

import           Security.AccessTokenProvider.Internal.Providers.Test
import           Security.AccessTokenProvider.Internal.Util.Test
import           Test.Tasty

securityAccessTokenProviderInternalTest :: [TestTree]
securityAccessTokenProviderInternalTest =
  [ testGroup "Security.AccessTokenProvider.Internal" $
    concat [ securityAccessTokenProviderInternalUtilTest
           , securityAccessTokenProviderInternalProvidersTest ]
  ]
