{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE QuasiQuotes         #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Security.AccessTokenProvider.Internal.Providers.Test
  ( securityAccessTokenProviderInternalProvidersTest
  ) where

import           Control.Exception.Safe
import           Control.Lens
import           Control.Monad.IO.Class
import qualified Data.ByteString.Lazy                       as ByteString.Lazy
import           Data.Format
import           Data.List.NonEmpty                         (NonEmpty (..))
import qualified Data.List.NonEmpty                         as NonEmpty
import qualified Data.Map.Strict                            as Map
import           Data.Semigroup
import qualified Data.Text.Encoding                         as Text
import           Data.UUID                                  (UUID)
import           Network.HTTP.Client.Internal
import           Network.HTTP.Types.Status
import           Network.HTTP.Types.Version
import           System.Random
import           Test.Tasty
import           Test.Tasty.HUnit

import           Security.AccessTokenProvider
import qualified Security.AccessTokenProvider               as ATP
import           Security.AccessTokenProvider.Internal.Util
import           Test

securityAccessTokenProviderInternalProvidersTest :: [TestTree]
securityAccessTokenProviderInternalProvidersTest =
  [ testGroup "Security.AccessTokenProvider.Internal.Providers"
    [ testCase "SimpleFixed Provider reads from TOKEN"
        simpleFixedProviderReadsFromToken
    , testCase "Fixed Provider reads from ATP_CONF"
        fixedProviderReadsFromConf
    , testCase "Fixed Provider reads from ATP_CONF and lookup fails"
        fixedProviderReadsFromConfLookupFails
    , testCase "File Provider reads from ATP_CONF"
        fileProviderReadsFromConf
    , testCase "File Provider reads from ATP_CONF and lookup fails"
        fileProviderReadsFromConfLookupFails
    , testCase "Ropcg Provider reads from ATP_CONF"
        ropcgProviderReadsFromConf
    ]
  ]

simpleFixedProviderReadsFromToken :: Assertion
simpleFixedProviderReadsFromToken = do
  token <- tshow <$> (randomIO :: IO UUID)
  let testState = TestState
                  { _testStateFilesystem = Map.empty
                  , _testStateEnvironment = Map.fromList [ ("TOKEN", token) ]
                  , _testStateHttpResponse = Nothing
                  , _testStateHttpRequests = []
                  , _testStateLog = []
                  }
  evalTestStack testState $ do
    tokenProvider <- newWithProviders mockBackend
                     (defaultProviders <> (AtpProbe providerProbeSimpleFixed :| []))
                     (AccessTokenName "some-random-token-name")
    (AccessToken token') <- retrieveAccessToken tokenProvider
    liftIO $ token @=? token'

fixedProviderReadsFromConf :: Assertion
fixedProviderReadsFromConf = do
  token <- tshow <$> (randomIO :: IO UUID)
  let conf = [fmt|{"provider": "fixed", "tokens": {"label1": "$token"}}|]
      testState = TestState
                  { _testStateFilesystem = Map.empty
                  , _testStateEnvironment = Map.fromList [ ("ATP_CONF_FIXED", conf) ]
                  , _testStateHttpResponse = Nothing
                  , _testStateHttpRequests = []
                  , _testStateLog = []
                  }
  evalTestStack testState $ do
    tokenProvider <- newWithBackend mockBackend (AccessTokenName "label1")
    (AccessToken token') <- retrieveAccessToken tokenProvider
    liftIO $ token @=? token'

fixedProviderReadsFromConfLookupFails :: Assertion
fixedProviderReadsFromConfLookupFails = do
  token <- tshow <$> (randomIO :: IO UUID)
  let conf = [fmt|{"provider": "fixed", "tokens": {"label1": "$token"}}|]
      testState = TestState
                  { _testStateFilesystem = Map.empty
                  , _testStateEnvironment = Map.fromList [ ("ATP_CONF_FIXED", conf) ]
                  , _testStateHttpResponse = Nothing
                  , _testStateHttpRequests = []
                  , _testStateLog = []
                  }
  evalTestStack testState $ do
    Left _ <- tryAny $ newWithBackend mockBackend (AccessTokenName "label2")
    pure ()

fileProviderReadsFromConf :: Assertion
fileProviderReadsFromConf = do
  tokenText <- tshow <$> (randomIO :: IO UUID)
  let tokenBytes = Text.encodeUtf8 tokenText
      filename = "/a/b/c"
      conf = [fmt|{"provider": "file", "tokens": {"label1": "$filename"}}|]
      testState = TestState
                  { _testStateFilesystem =
                      Map.fromList [ (filename, tokenBytes) ]
                  , _testStateEnvironment =
                      Map.fromList [ ("ATP_CONF_FILE", conf) ]
                  , _testStateHttpResponse = Nothing
                  , _testStateHttpRequests = []
                  , _testStateLog = []
                  }
  evalTestStack testState $ do
    tokenProvider <- newWithBackend mockBackend (AccessTokenName "label1")
    (AccessToken token') <- retrieveAccessToken tokenProvider
    liftIO $ tokenText @=? token'

fileProviderReadsFromConfLookupFails :: Assertion
fileProviderReadsFromConfLookupFails = do
  tokenText <- tshow <$> (randomIO :: IO UUID)
  let tokenBytes = Text.encodeUtf8 tokenText
      filename = "/a/b/c"
      conf = [fmt|{"provider": "file", "tokens": {"label1": "$filename"}}|]
      testState = TestState
                  { _testStateFilesystem =
                      Map.fromList [ (filename, tokenBytes) ]
                  , _testStateEnvironment =
                      Map.fromList [ ("ATP_CONF_FILE", conf) ]
                  , _testStateHttpResponse = Nothing
                  , _testStateHttpRequests = []
                  , _testStateLog = []
                  }
  evalTestStack testState $ do
    Left _ <- tryAny $ newWithBackend mockBackend (AccessTokenName "label2")
    pure ()

ropcgProviderReadsFromConf :: Assertion
ropcgProviderReadsFromConf = do
  tokenText <- tshow <$> (randomIO :: IO UUID)
  let conf = [fmt|{ "provider": "ropcg",
                    "credentials_directory": "/credentials",
                    "auth_endpoint": "https://localhost",
                    "tokens": {"label1": {"scopes": ["foo"]}}
                  }|]
      rspBody = ByteString.Lazy.fromStrict . Text.encodeUtf8 $
        [fmt|{"scope":        "foo",
              "expires_in":   60,
              "token_type":   "test",
              "access_token": "$tokenText"
             }|]
      response = Response { responseStatus    = ok200
                          , responseVersion   = http20
                          , responseHeaders   = []
                          , responseBody      = rspBody
                          , responseCookieJar = CJ []
                          , responseClose'    = ResponseClose (pure ())
                          }
      userCredentials =
        "{ \"application_username\": \"some-application-username\", \
        \  \"application_password\": \"some-application-password\" }"
      clientCredentials =
        "{ \"client_id\":     \"some-client-id\", \
        \  \"client_secret\": \"some-client-secret\" }"

      testState = TestState
                  { _testStateFilesystem   = Map.fromList
                    [ ("/credentials/user.json",   userCredentials)
                    , ("/credentials/client.json", clientCredentials)
                    ]
                  , _testStateEnvironment  = Map.fromList [ ("ATP_CONF_ROPCG", conf) ]
                  , _testStateHttpResponse = Just response
                  , _testStateHttpRequests = []
                  , _testStateLog = []
                  }
  (_, testState') <- runTestStack testState $ do
    tokenProvider <- newWithBackend mockBackend (AccessTokenName "label1")
    (AccessToken token) <- retrieveAccessToken tokenProvider
    liftIO $ tokenText @=? token
    pure ()
  1 @=? length (testState'^.testStateHttpRequests)
  pure ()

retrieveSomeToken :: IO ()
retrieveSomeToken = do
  tokenProvider <- ATP.new (AccessTokenName "token-name")
  token <- ATP.retrieveAccessToken tokenProvider
  print token
