{-# OPTIONS_GHC -Wno-orphans #-}
{-# OPTIONS_HADDOCK not-home #-}

module Wai.SessionCookie
   ( -- * Data
    Session
   , sessionRequestData
   , sessionSetOnResponse
   , sessionDeleteOnResponse

    -- * Middleware
   , middleware

    -- * Config
   , Config (..)
   , defaultConfig

    -- * Codecs
   , Codec (..)

    -- * Encryption
   , Encryption (..)
   )
where

import Data.Aeson qualified as Ae
import Data.Binary qualified as Bin
import Web.Cookie (SetCookie (..), defaultSetCookie, sameSiteLax)

import Wai.SessionCookie.AEAD_AES_128_GCM_SIV ()
import Wai.SessionCookie.AEAD_AES_256_GCM_SIV ()
import Wai.SessionCookie.Internal

instance (Bin.Binary a) => Codec "binary" a where
   encode _ = Bin.encode
   decode _ bl = case Bin.decodeOrFail bl of
      Right (_, _, a) -> Just a
      Left _ -> Nothing
   {-# INLINE encode #-}
   {-# INLINE decode #-}

instance (Ae.FromJSON a, Ae.ToJSON a) => Codec "aeson" a where
   encode _ = Ae.encode
   decode _ = Ae.decode
   {-# INLINE encode #-}
   {-# INLINE decode #-}

defaultConfig
   :: Key "AEAD_AES_128_GCM_SIV"
   -> Config "aeson" "AEAD_AES_128_GCM_SIV" a
defaultConfig key =
   Config
      { key
      , setCookie =
         defaultSetCookie
            { setCookieDomain = Nothing
            , setCookieExpires = Nothing
            , setCookieHttpOnly = True
            , setCookieMaxAge = Just (16 * 60 * 60)
            , setCookieName = "SESSION"
            , setCookiePath = Just "/"
            , setCookieSameSite = Just sameSiteLax
            , setCookieSecure = True
            , setCookieValue = error "setCookieValue"
            }
      }
