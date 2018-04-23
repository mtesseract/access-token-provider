{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Test.Tasty

import           Security.AccessTokenProvider.Test

main :: IO ()
main = do
  putStrLn ""
  defaultMain tests

tests :: TestTree
tests =
  testGroup "Access Token Provider Test Suite"
    [securityAccessTokenProviderTests]
