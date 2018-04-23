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
import           Control.Monad.Catch                         hiding (bracket)
import           Control.Monad.IO.Class
import           Control.Monad.IO.Unlift
import           Control.Monad.Reader
import           Control.Monad.State
import           Data.ByteString                             (ByteString)
import qualified Data.ByteString.Lazy                        as ByteString.Lazy
import           Data.IORef
import           Data.Map.Strict                             (Map)
import qualified Data.Map.Strict                             as Map
import           Data.Text                                   (Text)
import           Katip
import           Katip.Monadic
import           Network.HTTP.Client
import           System.IO
import           UnliftIO.Exception

import           Security.AccessTokenProvider.Internal.Types

runTestStack :: TestState -> TestStack a -> IO (a, TestState)
runTestStack testState m = do
  s <- newIORef testState
  a <- m & (_runTestStack
            >>> runKatip
            >>> flip runReaderT s)
  (a,) <$> readIORef s

runKatip :: MonadUnliftIO m => KatipContextT m a -> m a
runKatip m = do
  handleScribe <- liftIO $ mkHandleScribe ColorIfTerminal stdout WarningS V2
  let makeLogEnv = do
        logEnv <- initLogEnv "test-suite" "test"
        registerScribe "stdout" handleScribe defaultScribeSettings logEnv
  bracket (liftIO makeLogEnv) (liftIO . closeScribes) $ \ logEnv -> do
    let initialContext = ()
    let initialNamespace = "main"
    runKatipContextT logEnv initialContext initialNamespace m

evalTestStack :: TestState -> TestStack a -> IO a
evalTestStack testState m = do
  s <- newIORef testState
  m & (_runTestStack
       >>> runKatip
       >>> flip runReaderT s)

newtype TestStack a = TestStack
  { _runTestStack :: KatipContextT (ReaderT (IORef TestState) IO) a
  } deriving ( Functor
             , Applicative
             , Monad
             , MonadThrow
             , MonadCatch
             , MonadMask
             , MonadReader (IORef TestState)
             , MonadIO
             , Katip
             , KatipContext
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
            }

makeFieldsNoPrefix ''TestState

instance MonadState TestState TestStack where
  get = do
    envRef <- ask
    liftIO $ readIORef envRef
  put s = do
    envRef <- ask
    liftIO $ writeIORef envRef s

instance MonadEnvironment TestStack where
  environmentLookup name =
    Map.lookup name <$> gets (view testStateEnvironment)

instance MonadFilesystem TestStack where
  fileRead filename = do
    fs <- gets (view testStateFilesystem)
    case Map.lookup filename fs of
      Just bytes -> pure bytes
      _          -> error "FIXME: file not found"

instance MonadHttp TestStack where
  httpRequestExecute request _manager = do
    testStateHttpRequests %= (request :)
    maybeResponse <- gets (view testStateHttpResponse)
    case maybeResponse of
      Just response ->
        pure response
      Nothing ->
        error "FIXME"
