{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE PolyKinds             #-}
{-# LANGUAGE Rank2Types            #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}

module Security.AccessTokenProvider.Internal where

import           Control.Arrow
import           Control.Exception.Safe
import           Control.Monad.IO.Unlift
import           Data.ByteString                                              (ByteString)
import qualified Data.ByteString                                              as ByteString
import           Data.List.NonEmpty                                           (NonEmpty (..))
import qualified Data.List.NonEmpty                                           as NonEmpty
import           Data.Monoid
import           Data.Text                                                    (Text)
import qualified Data.Text                                                    as Text
import qualified Katip                                                        as Katip
import           Network.HTTP.Client
import           Network.HTTP.Client.TLS
import qualified System.Environment                                           as Env

import           Say
import           Security.AccessTokenProvider.Internal.Providers.File
import           Security.AccessTokenProvider.Internal.Providers.Fixed
import           Security.AccessTokenProvider.Internal.Providers.OAuth2.Ropcg
import           Security.AccessTokenProvider.Internal.Types
import           Security.AccessTokenProvider.Internal.Types.Severity
import           Security.AccessTokenProvider.Internal.Util

import           Security.AccessTokenProvider.Internal.Types.Severity         (Severity)

namespace :: Text
namespace = "access-token-provider"

-- | Create a new access token provider, specifying backend and list
-- of providers.
newWithProviders
  :: MonadThrow m
  => Backend m             -- ^ Backend to use.
  -> NonEmpty (AtpProbe m) -- ^ List of providers to use.
  -> AccessTokenName       -- ^ Name of the access token to create a
                           -- provider for.
  -> m (AccessTokenProvider m t)
newWithProviders backend providers tokenName = do
  let BackendLog { .. } = backendLog backend
  logAddNamespace namespace $
    probeProviders (NonEmpty.toList providers)

  where probeProviders [] =
          throwM $ AccessTokenProviderMissing tokenName
        probeProviders (AtpProbe tryProvider : rest) = do
          maybeProvider <- tryProvider backend tokenName
          case maybeProvider of
            Nothing ->
              probeProviders rest
            Just provider ->
              pure provider

-- | Create a new access token provider using the default IO-based
-- backend and the default providers.
new
  :: (MonadUnliftIO m, MonadMask m)
  => AccessTokenName -- ^ Name of the access token to create a
                     -- provider for.
  -> m (AccessTokenProvider m t)
new = newWithProviders backendIO defaultProviders

-- | List of default providers: Fixed (environment) provider,
-- file-based provider, OAuth2
-- Resource-Owner-Password-Credentials-Grant provider.
defaultProviders :: (MonadUnliftIO m, MonadMask m)
                 => NonEmpty (AtpProbe m)
defaultProviders =
  probeProviderFixed :| [ probeProviderFile, probeProviderRopcg ]

httpBackendIO :: MonadIO m => BackendHttp m
httpBackendIO =
  BackendHttp { httpRequestExecute = httpRequestExecuteIO }
  where httpRequestExecuteIO :: MonadIO m => Request -> m (Response LazyByteString)
        httpRequestExecuteIO request = do
          manager <- liftIO getGlobalManager
          liftIO $ httpLbs request manager

envBackendIO :: MonadIO m => BackendEnv m
envBackendIO =
  BackendEnv { envLookup = envLookupIO }

  where envLookupIO :: MonadIO m => Text -> m (Maybe Text)
        envLookupIO =
          Text.unpack
          >>> Env.lookupEnv
          >>> fmap (fmap Text.pack)
          >>> liftIO

filesystemBackendIO :: MonadIO m => BackendFilesystem m
filesystemBackendIO =
  BackendFilesystem { fileRead = fileReadIO }
  where fileReadIO :: MonadIO m => FilePath ->  m ByteString
        fileReadIO = liftIO . ByteString.readFile

logBackendIO :: MonadIO m => BackendLog m
logBackendIO =
  BackendLog { logAddNamespace = \ _namespace -> id
             , logMsg          = logMsgIO
             }
  where logMsgIO :: MonadIO m => Severity -> Text -> m ()
        logMsgIO severity msg =
          say $ "[" <> tshow severity <> "] " <> msg

logBackendKatip :: Katip.KatipContext m => BackendLog m
logBackendKatip =
  BackendLog { logAddNamespace = \ nspace ->
                 Katip.katipAddNamespace (Katip.Namespace [nspace])
             , logMsg = \ severity msg ->
                 Katip.logFM (toKatipSeverity severity) (Katip.ls msg)
             }

-- | IO based backend using simple stdout logging via 'say'.
backendIO :: MonadIO m => Backend m
backendIO = Backend
  { backendHttp = httpBackendIO
  , backendEnv = envBackendIO
  , backendFilesystem = filesystemBackendIO
  , backendLog = logBackendIO
  }

-- | IO based backend using Katip for logging.
backendIOWithKatip :: Katip.KatipContext m => Backend m
backendIOWithKatip =
  backendIO { backendLog = logBackendKatip }

toKatipSeverity :: Severity -> Katip.Severity
toKatipSeverity severity =
  case severity of
    Debug   -> Katip.DebugS
    Info    -> Katip.InfoS
    Warning -> Katip.WarningS
    Error   -> Katip.ErrorS
    Alert   -> Katip.AlertS

-- | Create a new access token provider, specifying the backend to
-- use, using the default providers.
newWithBackend
  :: (MonadUnliftIO m, MonadMask m)
  => Backend m       -- ^ Backend to ue.
  -> AccessTokenName -- ^ Name of the access token to create a
                     -- provider for.
  -> m (AccessTokenProvider m t)
newWithBackend backend = newWithProviders backend defaultProviders
