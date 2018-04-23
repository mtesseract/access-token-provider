module Security.AccessTokenProvider.Test
  ( securityAccessTokenProviderTests
  ) where

import           Security.AccessTokenProvider.Internal.Test
import           Test.Tasty

securityAccessTokenProviderTests :: TestTree
securityAccessTokenProviderTests =
  testGroup "Security.AccessTokenProvider"
  securityAccessTokenProviderInternalTest
