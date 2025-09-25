{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE NoFieldSelectors #-}

-- | This module exports tools for safely storing encrypted data on client-side
-- cookies through "Network.Wai". Consider using it in conjunction with "Wai.CSRF".
module Wai.CryptoCookie
   ( -- * Config
    defaultConfig
   , Config (..)
   , CryptoCookie
   , newCryptoCookie

    -- * Request and responses
   , middleware
   , msgFromRequestCookie
   , setCookie
   , expireCookie

    -- * Encryption
   , Encryption (..)
   , autoKeyFileBase16
   , readKeyFileBase16
   , readKeyFile
   , writeKeyFile
   ) where

import Control.Monad.IO.Class
import Data.Aeson qualified as Ae
import Data.ByteArray.Encoding qualified as BA
import Data.ByteArray.Sized qualified as BAS
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as BL
import Data.IORef
import Data.Kind (Type)
import Data.Time.Clock.POSIX qualified as Time
import Network.Wai qualified as Wai
import Wai.CSRF qualified
import Wai.CryptoCookie.Encryption
import Wai.CryptoCookie.Encryption.AEAD_AES_128_GCM_SIV ()
import Wai.CryptoCookie.Encryption.AEAD_AES_256_GCM_SIV ()
import Web.Cookie qualified as WC

-- | Default 'Config':
--
-- * Cookie name is @SESSION@.
--
-- * Encoding and decoding of @msg@ is done through 'Ae.ToJSON' and
--   'Ae.FromJSON'.
--
-- * The 'Encryption' scheme is the nonce-misuse resistant @AEAD_AES_256_GCM_SIV@
--   as defined in in <https://tools.ietf.org/html/rfc8452 RFC 8452>, using
--   a "Wai.CSRF".'Wai.CSRF.Token' as AEAD associated data.
--
--     As an AEAD encryption scheme, you can be confident that a successfully
--     decrypted cookie could only have been encrypted by the same
--     'Key' known only to your server, and associated with a specific
--     "Wai.CSRF".'Wai.CSRF.Token', expected to have been sent with the
--     incoming request.
--
--     In principle, this makes this encryption scheme suitable for storing
--     server-generated user session data in the @msg@.  However, you must make
--     sure that you rotate the "Wai.CSRF".'Wai.CSRF.Token' ocassionally, at
--     least each time a new user session is established, so as to avoid CSRF
--     risks.
--
-- * This 'defaultConfig' suggests you should be composing 'middleware' and
--   "Wai.CSRF".'Wai.CSRF.middleware' in this way:
--
--      @
--      "Wai.CSRF".'Wai.CSRF.middleware' /myCsrfConfig/
--         . "Wai.CryptoCookie".'middleware' /myCryptoCookie/
--              :: ('Maybe' ("Wai.CSRF".'Wai.CSRF.Token', msg) -> 'Wai.Application')
--              -> 'Wai.Application'
--      @
defaultConfig
   :: (Ae.ToJSON msg, Ae.FromJSON msg)
   => Key "AEAD_AES_256_GCM_SIV"
   -- ^ Consider using 'autoKeyFileBase16' or
   -- 'readKeyFileBase16' for safely reading a 'Key' from a
   -- 'FilePath'. Alternatively, if you have the base-16 representation of the
   -- 'Key' in JSON configuration, you could use
   -- 'Data.Aeson.FromJSON'.
   -> Config Wai.CSRF.Token msg
defaultConfig key =
   Config
      { cookieName = "SESSION"
      , key
      , aadEncode = \(Wai.CSRF.Token t) ->
         BL.fromStrict $ BAS.unSizedByteArray t
      , msgEncode = Ae.encode
      , msgDecode = Ae.decode
      }

-- | Configuration for 'CryptoCookie'.
--
-- Consider using 'defaultConfig' and updating desired fields only.
data Config (aad :: Type) (msg :: Type) = forall e.
    (Encryption e) =>
   Config
   { cookieName :: B.ByteString
   -- ^ Consider using a @\"SESSION\"@.
   , key :: Key e
   -- ^ Consider using a @'Key' \"AEAD_AES_256_GCM_SIV\"@.
   , aadEncode :: aad -> BL.ByteString
   -- ^ These are the exact bytes that will be used as AEAD associated data.
   -- Consider using the raw bytes of a "Wai.CSRF".'Wai.CSRF.Token'.
   , msgEncode :: msg -> BL.ByteString
   -- ^ These are the exact bytes that will be encrypted.
   , msgDecode :: BL.ByteString -> Maybe msg
   -- ^ Undo what @msgEncode@ did, if possible.
   }

-- | Stateful encryption environment for interacting with the encrypted cookie.
--
-- It is safe to use 'CryptoCookie' concurrently if necessary. Concurrency is handled
-- safely internally.
--
-- Obtain with 'newCryptoCookie'.
data CryptoCookie (aad :: Type) (msg :: Type) = CryptoCookie
   { cookieName :: B.ByteString
   , encodeEncrypt :: aad -> msg -> IO BL.ByteString
   , decryptDecode :: aad -> BL.ByteString -> Maybe msg
   }

--------------------------------------------------------------------------------

-- | Obtain a new 'CryptoCookie'.
newCryptoCookie :: (MonadIO m) => Config aad msg -> m (CryptoCookie aad msg)
newCryptoCookie c@Config{key} = liftIO do
   let dc = initDecrypt key
   ecRef <- newIORef =<< initEncrypt key
   pure
      CryptoCookie
         { encodeEncrypt = \aad0 msg0 -> do
            let !aad1 :: BL.ByteString = c.aadEncode aad0
                !msg1 :: BL.ByteString = c.msgEncode msg0
            ec <- atomicModifyIORef' ecRef \ec -> (advance ec, ec)
            pure $ encrypt ec aad1 msg1
         , decryptDecode = \aad0 !cry -> do
            let !aad1 = c.aadEncode aad0
            case decrypt dc aad1 cry of
               Right msg -> c.msgDecode msg
               _ -> Nothing
         , cookieName = c.cookieName
         }

-- | Transform an 'Wai.Application' so that if there is an encrypted
-- message in the incoming 'Wai.Request' cookies, it will be automatically
-- decrypted and made available to the underlying 'Wai.Application'.
--
-- The @aad@ is the AEAD associated data that came with the 'Wai.Request'.
-- Consider using 'middleware' in conjunction with
-- "Wai.CSRF".'Wai.CSRF.middleware', using "Wai.CSRF".'Wai.CSRF.Token' as
-- @aad@.
middleware
   :: CryptoCookie aad msg
   -- ^ Encryption environment. Obtain with 'newCryptoCookie'.
   -> (Maybe (aad, Maybe msg) -> Wai.Application)
   -- ^ Underlying 'Wai.Application' having access to the decrypted cookie
   -- @msg@, if any.
   --
   -- Also, seeing as @msg@ being available implies @aad@ is available too, we
   -- output both values together in a manner that represents this relationship.
   -> Maybe aad
   -- ^ AEAD associated data of the incomming 'Wai.Request', if any.
   -> Wai.Application
middleware cc fapp yaad req respond = do
   let ymsg = msgFromRequestCookie cc req =<< yaad
   fapp (fmap (,ymsg) yaad) req respond

-- | Obtain the @msg@ from the 'Wai.Request' cookies.
--
-- You don't need to use this if you are using 'middleware'.
msgFromRequestCookie :: CryptoCookie aad msg -> Wai.Request -> aad -> Maybe msg
msgFromRequestCookie cc r aad = do
   [d64] <- pure $ lookupMany cc.cookieName $ requestCookies r
   case BA.convertFromBase BA.Base64URLUnpadded d64 of
      Right cry -> cc.decryptDecode aad $ BL.fromStrict cry
      Left _ -> Nothing

--------------------------------------------------------------------------------

-- | Construct a 'C.SetCookie' containing the encrypted @msg@.
--
-- The associated data @aad@ will not be included in this cookie, but it will
-- be taken into account for encryption and necessary for eventual decryption.
--
-- The 'C.SetCookie' has these settings, some of which could be overriden.
--
--      * Cookie name is 'Config'\'s @cookieName@.
--
--      * @HttpOnly@: Yes, and you shouldn't change this.
--
--      * @Max-Age@ and @Expires@: This cookie never expires. We recommend
--      relying on server-side expiration instead, as the lifetime of the
--      cookie could easily be extended by a legitimate but malicious client.
--      You can store a creation or expiration timestamp inside @msg@, and
--      make a decision based on that.
--
--      * @Path@: @\/@
--
--      * @SameSite@: @Lax@.
--
--      * @Secure@: Yes.
--
--      * @Domain@: Not set.
--
-- Note: If you are using "Wai.CSRF".'Wai.CSRF.Token' as @aad@, it is
-- recommended that you generate a new "Wai.CSRF".'Wai.CSRF.Token' at least
-- each time a new user session is established, but possibly more frequently,
-- and send it alongside this one (see "Wai.CSRF".'Wai.CSRF.setCookie').
setCookie :: (MonadIO m) => CryptoCookie aad msg -> aad -> msg -> m WC.SetCookie
setCookie cc aad msg = liftIO do
   cry <- cc.encodeEncrypt aad msg
   pure $
      (expireCookie cc)
         { WC.setCookieExpires = Nothing
         , WC.setCookieMaxAge = Nothing
         , WC.setCookieValue =
            BA.convertToBase BA.Base64URLUnpadded $ BL.toStrict cry
         }

-- | Construct a 'C.SetCookie' expiring the cookie named 'Config'\'s
-- @cookieName@.
expireCookie :: CryptoCookie aad msg -> WC.SetCookie
expireCookie cc =
   WC.defaultSetCookie
      { WC.setCookieDomain = Nothing
      , WC.setCookieExpires = Just (Time.posixSecondsToUTCTime 0)
      , WC.setCookieHttpOnly = True
      , WC.setCookieMaxAge = Just (negate 1)
      , WC.setCookieName = cc.cookieName
      , WC.setCookiePath = Just "/"
      , WC.setCookieSameSite = Just WC.sameSiteLax
      , WC.setCookieSecure = True
      , WC.setCookieValue = ""
      }

--------------------------------------------------------------------------------

requestCookies :: Wai.Request -> [(B.ByteString, B.ByteString)]
requestCookies r =
   WC.parseCookies =<< lookupMany "Cookie" (Wai.requestHeaders r)

lookupMany :: (Eq k) => k -> [(k, v)] -> [v]
lookupMany k = findMany (== k)

findMany :: (Eq k) => (k -> Bool) -> [(k, v)] -> [v]
findMany f = map snd . filter (\(a, _) -> f a)
