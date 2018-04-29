{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE FunctionalDependencies     #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE TypeSynonymInstances       #-}


module Test where

import           Control.Arrow
import           Control.Lens
import           Control.Monad.Catch                                  hiding
                                                                       (bracket)
import           Control.Monad.IO.Class
import           Control.Monad.IO.Unlift
import           Control.Monad.Reader
import           Control.Monad.State
import           Data.ByteString                                      (ByteString)
import qualified Data.ByteString.Lazy                                 as ByteString.Lazy
import           Data.IORef
import           Data.Map.Strict                                      (Map)
import qualified Data.Map.Strict                                      as Map
import           Data.Text                                            (Text)
import           Network.HTTP.Client

import           Security.AccessTokenProvider.Internal.Types
import           Security.AccessTokenProvider.Internal.Types.Severity

runTestStack :: TestState -> TestStack a -> IO (a, TestState)
runTestStack testState m = do
  s <- newIORef testState
  a <- m & (_runTestStack
            >>> flip runReaderT s)
  (a,) <$> readIORef s

evalTestStack :: TestState -> TestStack a -> IO a
evalTestStack testState m = do
  s <- newIORef testState
  m & (_runTestStack
       >>> flip runReaderT s)

newtype TestStack a = TestStack
  { _runTestStack :: ReaderT (IORef TestState) IO a
  } deriving ( Functor
             , Applicative
             , Monad
             , MonadThrow
             , MonadCatch
             , MonadMask
             , MonadReader (IORef TestState)
             , MonadIO
             )

instance MonadUnliftIO TestStack where
  askUnliftIO = do
    (UnliftIO u) <- TestStack askUnliftIO
    pure $ UnliftIO (\ (TestStack m) -> u m)

data TestState =
  TestState { _testStateFilesystem   :: Map FilePath ByteString
            , _testStateEnvironment  :: Map Text Text
            , _testStateHttpRequests :: [Request]
            , _testStateHttpResponse :: Maybe (Response ByteString.Lazy.ByteString)
            , _testStateLog          :: [(Severity, Text)]
            }

makeFieldsNoPrefix ''TestState

instance MonadState TestState TestStack where
  get = do
    envRef <- ask
    liftIO $ readIORef envRef
  put s = do
    envRef <- ask
    liftIO $ writeIORef envRef s

mockBackend :: Backend TestStack
mockBackend =
  Backend { backendHttp       = mockBackendHttp
          , backendEnv        = mockBackendEnv
          , backendFilesystem = mockBackendFilesystem
          , backendLog        = mockBackendLog
          }

mockBackendHttp :: BackendHttp TestStack
mockBackendHttp =
  BackendHttp { httpRequestExecute = \ request -> do
                  testStateHttpRequests %= (request :)
                  maybeResponse <- gets (view testStateHttpResponse)
                  case maybeResponse of
                    Just response ->
                      pure response
                    Nothing ->
                      error "FIXME"
              }

mockBackendEnv :: BackendEnv TestStack
mockBackendEnv =
  BackendEnv { envLookup = \ name ->
                 Map.lookup name <$> gets (view testStateEnvironment)
              }

mockBackendFilesystem :: BackendFilesystem TestStack
mockBackendFilesystem =
  BackendFilesystem { fileRead = \ filename -> do
                        fs <- gets (view testStateFilesystem)
                        case Map.lookup filename fs of
                          Just bytes ->
                            pure bytes
                          Nothing ->
                            error "FIXME: file not found"
                    }

mockBackendLog :: BackendLog TestStack
mockBackendLog =
  BackendLog { logAddNamespace = \ _namespace -> id
             , logMsg = \ severity msg ->
                 modify (testStateLog %~ ((severity, msg) :))
             }
