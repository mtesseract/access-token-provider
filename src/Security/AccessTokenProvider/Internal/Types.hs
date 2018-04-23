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

import           Control.Arrow
import           Control.Exception
import           Control.Monad.IO.Class
import           Control.Monad.Reader
import           Control.Monad.Trans.Maybe
import           Control.Monad.Trans.State
import           Data.Aeson
import           Data.Aeson.Casing
import           Data.Aeson.TH
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as ByteString
import qualified Data.ByteString.Lazy      as ByteString.Lazy
import           Data.Format
import           Data.Map.Strict           (Map)
import           Data.String
import           Data.Text                 (Text)
import qualified Data.Text                 as Text
import           Data.Typeable
import           GHC.Generics
import           Katip
import           Network.HTTP.Client
import qualified System.Environment        as Env

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
  AtpProbe (forall t. AccessTokenName -> m (Maybe (AccessTokenProvider m t)) )

class Monad m => MonadFilesystem m where
  fileRead :: FilePath -> m ByteString
  default fileRead :: (m ~ t n, MonadTrans t, MonadFilesystem n) => FilePath -> m ByteString
  fileRead = lift . fileRead

instance MonadFilesystem IO where
  fileRead = ByteString.readFile

instance MonadFilesystem m => MonadFilesystem (ReaderT r m)
instance MonadFilesystem m => MonadFilesystem (MaybeT m)
instance MonadFilesystem m => MonadFilesystem (KatipContextT m)
instance MonadFilesystem m => MonadFilesystem (KatipT m)
instance MonadFilesystem m => MonadFilesystem (StateT s m)

class Monad m => MonadEnvironment m where
  environmentLookup :: Text -> m (Maybe Text)
  default environmentLookup :: (m ~ t n, MonadTrans t, MonadEnvironment n)
                            => Text
                            -> m (Maybe Text)
  environmentLookup = lift . environmentLookup

instance MonadEnvironment IO where
  environmentLookup =
    Text.unpack
    >>> Env.lookupEnv
    >>> liftIO
    >>> fmap (fmap Text.pack)

instance MonadEnvironment m => MonadEnvironment (ReaderT r m)
instance MonadEnvironment m => MonadEnvironment (MaybeT m)
instance MonadEnvironment m => MonadEnvironment (KatipContextT m)
instance MonadEnvironment m => MonadEnvironment (KatipT m)
instance MonadEnvironment m => MonadEnvironment (StateT s m)

class Monad m => MonadHttp m where
  httpRequestExecute :: Request -> Manager -> m (Response  LazyByteString)
  default httpRequestExecute :: (m ~ t n, MonadTrans t, MonadHttp n)
                             => Request
                             -> Manager
                             -> m (Response  LazyByteString)
  httpRequestExecute req manager = lift $ httpRequestExecute req manager

instance MonadHttp IO where
  httpRequestExecute = httpLbs

instance MonadHttp m => MonadHttp (ReaderT r m)
instance MonadHttp m => MonadHttp (MaybeT m)
instance MonadHttp m => MonadHttp (KatipContextT m)
instance MonadHttp m => MonadHttp (KatipT m)
instance MonadHttp m => MonadHttp (StateT s m)
