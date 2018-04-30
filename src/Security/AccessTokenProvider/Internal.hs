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

newWithProviders
  :: MonadThrow m
  => Backend m
  -> NonEmpty (AtpProbe m)
  -> AccessTokenName
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

new
  :: (MonadUnliftIO m, MonadMask m)
  => AccessTokenName -> m (AccessTokenProvider m t)
new = newWithProviders backendIO defaultProviders

defaultProviders :: (MonadUnliftIO m, MonadMask m)
                 => NonEmpty (AtpProbe m)
defaultProviders =
  probeProviderFixed :| [ probeProviderFile, probeProviderRopcg ]

httpRequestExecuteIO :: MonadIO m => Request -> m (Response LazyByteString)
httpRequestExecuteIO request = do
  manager <- liftIO getGlobalManager
  liftIO $ httpLbs request manager

envLookupIO :: MonadIO m => Text -> m (Maybe Text)
envLookupIO =
  Text.unpack
  >>> Env.lookupEnv
  >>> fmap (fmap Text.pack)
  >>> liftIO

fileReadIO :: MonadIO m => FilePath ->  m ByteString
fileReadIO = liftIO . ByteString.readFile

backendIO :: MonadIO m => Backend m
backendIO = Backend
  { backendHttp = BackendHttp { httpRequestExecute = httpRequestExecuteIO }
  , backendEnv = BackendEnv { envLookup = envLookupIO }
  , backendFilesystem = BackendFilesystem { fileRead = fileReadIO }
  , backendLog = BackendLog { logAddNamespace = \ _namespace -> id
                            , logMsg          = logMsgIO
                            }
  }

backendIOWithKatip :: Katip.KatipContext m => Backend m
backendIOWithKatip =
  backendIO { backendLog = backendLogKatip }

backendLogKatip :: Katip.KatipContext m => BackendLog m
backendLogKatip =
  BackendLog { logAddNamespace = \ nspace ->
                 Katip.katipAddNamespace (Katip.Namespace [nspace])
             , logMsg = \ severity msg ->
                 Katip.logFM (toKatipSeverity severity) (Katip.ls msg)
             }

toKatipSeverity :: Severity -> Katip.Severity
toKatipSeverity severity =
  case severity of
    Debug   -> Katip.DebugS
    Info    -> Katip.InfoS
    Warning -> Katip.WarningS
    Error   -> Katip.ErrorS
    Alert   -> Katip.AlertS

logMsgIO :: MonadIO m => Severity -> Text -> m ()
logMsgIO severity msg =
  say $ "[" <> tshow severity <> "] " <> msg

newWithBackend
  :: (MonadUnliftIO m, MonadMask m)
  => Backend m
  -> AccessTokenName
  -> m (AccessTokenProvider m t)
newWithBackend backend = newWithProviders backend defaultProviders
