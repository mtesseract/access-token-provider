{-# LANGUAGE DefaultSignatures          #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DuplicateRecordFields      #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}

module Security.AccessTokenProvider.Internal.Types where

import           Control.Exception
import           Data.Aeson                                           hiding
                                                                       (Error)
import           Data.Aeson.Casing
import           Data.Aeson.TH
import           Data.ByteString                                      (ByteString)
import qualified Data.ByteString.Lazy                                 as ByteString.Lazy
import           Data.Format
import           Data.Map.Strict                                      (Map)
import           Data.String
import           Data.Text                                            (Text)
import           Data.Typeable
import           GHC.Generics
import           Network.HTTP.Client

import           Security.AccessTokenProvider.Internal.Types.Severity

type LazyByteString = ByteString.Lazy.ByteString

data AccessTokenProvider (m :: * -> * ) t =
  AccessTokenProvider { retrieveAccessToken :: m (AccessToken t)
                      , releaseProvider     :: m () }

newtype AccessToken t =
  AccessToken { unAccessToken :: Text
              } deriving (Eq, Ord, Show)

newtype AccessTokenName = AccessTokenName Text
  deriving (Eq, Ord, Show, IsString)

$(deriveJSON defaultOptions ''AccessTokenName)

instance Format AccessTokenName where
  formatText (AccessTokenName tokenName) = tokenName

data AtpConfFixed =
  AtpConfFixed { _tokens :: Maybe (Map Text Text)
               , _token  :: Maybe Text
               } deriving (Eq, Show, Generic)

$(deriveJSON (aesonDrop 1 snakeCase) ''AtpConfFixed)

data AtpConfFile =
  AtpConfFile { _tokens :: Maybe (Map Text FilePath)
              , _token  :: Maybe FilePath
              } deriving (Eq, Show, Generic)

$(deriveJSON (aesonDrop 1 snakeCase) ''AtpConfFile)

newtype AtpRopcgTokenDef =
  AtpRopcgTokenDef { _scopes :: [Text]
                   } deriving (Eq, Show, Generic)

$(deriveJSON (aesonDrop 1 snakeCase) ''AtpRopcgTokenDef)

data AtpPreconfRopcg =
  AtpPreconfRopcg
  { _credentialsDirectory      :: Maybe FilePath
  , _clientPasswordFile        :: Maybe FilePath
  , _resourceOwnerPasswordFile :: Maybe FilePath
  , _refreshTimeFactor         :: Maybe Double
  , _authEndpoint              :: Text
  , _tokens                    :: Map Text AtpRopcgTokenDef
  , _token                     :: Maybe AtpRopcgTokenDef
  } deriving (Eq, Show, Generic)

$(deriveJSON (aesonDrop 1 snakeCase) ''AtpPreconfRopcg)

data AtpConfRopcg =
  AtpConfRopcg
  { _credentialsDirectory      :: FilePath
  , _clientPasswordFile        :: FilePath
  , _resourceOwnerPasswordFile :: FilePath
  , _refreshTimeFactor         :: Double
  , _authEndpoint              :: Request
  , _manager                   :: Manager
  , _tokens                    :: Map Text AtpRopcgTokenDef
  , _token                     :: Maybe AtpRopcgTokenDef
  } deriving (Generic)

-- | Type modelling the content of the credentials stored in a
-- client.json file.
data ClientCredentials =
  ClientCredentials { _clientId     :: Text
                    , _clientSecret :: Text
                    } deriving (Generic, Show, Eq)

$(deriveJSON (aesonDrop 1 snakeCase) ''ClientCredentials)


-- | Type modelling the content of the credentials stored in a
-- user.json file.
data UserCredentials =
  UserCredentials { _applicationUsername :: Text
                  , _applicationPassword :: Text
                  } deriving (Generic, Show, Eq)

$(deriveJSON (aesonDrop 1 snakeCase) ''UserCredentials)

-- | Type for RFC7807 @Problem@ objects.
data OAuth2Error = OAuth2Error
  { oauth2Error            :: Text
  , oauth2ErrorDescription :: Maybe Text
  , oauth2ErrorURI         :: Maybe Text
  , oauth2ErrorState       :: Maybe Text
  } deriving (Show, Eq, Generic)

instance ToJSON OAuth2Error where
   toJSON = genericToJSON $ aesonDrop 6 snakeCase
instance FromJSON OAuth2Error where
   parseJSON = genericParseJSON $ aesonDrop 6 snakeCase


data AccessTokenProviderException
  = AccessTokenProviderRefreshFailure OAuth2Error
  | AccessTokenProviderDeserialization Text
  | AccessTokenProviderTokenMissing
  | AccessTokenProviderMissing AccessTokenName
 deriving (Typeable, Show)

instance Exception AccessTokenProviderException

-- | Type containing all credentials read from a mint credentials
-- directory.
data Credentials =
  Credentials { _user   :: UserCredentials
              , _client :: ClientCredentials }

data AtpRopcgResponse =
  AtpRopcgResponse { _scope       :: Maybe Text
                   , _expiresIn   :: Maybe Int -- Validity in seconds
                   , _tokenType   :: Text
                   , _accessToken :: Text
                   } deriving (Generic, Show, Eq)

$(deriveJSON (aesonDrop 1 snakeCase) ''AtpRopcgResponse)

newtype AtpProbe m =
  AtpProbe (forall t. Backend m -> AccessTokenName -> m (Maybe (AccessTokenProvider m t)) )

data BackendHttp m = BackendHttp
  { httpRequestExecute :: Request -> m (Response LazyByteString)
  }

data BackendEnv m = BackendEnv
  { envLookup :: Text -> m (Maybe Text)
  }

data BackendFilesystem m = BackendFilesystem
  { fileRead :: FilePath -> m ByteString
  }

data BackendLog m = BackendLog
  { logAddNamespace :: forall a. Text -> m a -> m a
  , logMsg          :: Severity -> Text -> m ()
  }

data Backend m = Backend
  { backendHttp       :: BackendHttp m
  , backendEnv        :: BackendEnv m
  , backendFilesystem :: BackendFilesystem m
  , backendLog        :: BackendLog m
  }
