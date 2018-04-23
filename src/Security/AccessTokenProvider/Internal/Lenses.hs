{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE TemplateHaskell        #-}
{-# LANGUAGE TypeSynonymInstances   #-}

module Security.AccessTokenProvider.Internal.Lenses where

import           Control.Lens

import           Security.AccessTokenProvider.Internal.Types

makeFieldsNoPrefix ''AtpConfRopcg
makeFieldsNoPrefix ''AtpConfFile
makeFieldsNoPrefix ''AtpConfFixed
makeFieldsNoPrefix ''AtpPreconfRopcg
makeFieldsNoPrefix ''AtpRopcgTokenDef
makeFieldsNoPrefix ''ClientCredentials
makeFieldsNoPrefix ''UserCredentials
makeFieldsNoPrefix ''Credentials
makeFieldsNoPrefix ''AtpRopcgResponse
