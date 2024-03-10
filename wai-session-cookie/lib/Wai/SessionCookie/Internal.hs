{-# LANGUAGE StrictData #-}
{-# LANGUAGE NoFieldSelectors #-}

module Wai.SessionCookie.Internal where

import Control.Concurrent.STM
import Control.Monad.IO.Class
import Crypto.Random qualified as C
import Data.ByteArray qualified as BA
import Data.ByteArray.Encoding qualified as BA
import Data.ByteArray.Sized qualified as BAS
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as BL
import Data.IORef
import Data.Kind (Type)
import Data.List (find)
import Data.Proxy
import Data.Time.Clock.POSIX qualified as Time
import Data.Vault.Lazy qualified as V
import GHC.TypeLits (Symbol)
import Network.Wai qualified as Wai
import Numeric.Natural
import Web.Cookie
   ( SetCookie (..)
   , parseCookies
   , parseSetCookie
   , renderSetCookieBS
   )

class Codec (c :: Symbol) (a :: Type) where
   encode :: Proxy c -> a -> BL.ByteString
   decode :: Proxy c -> BL.ByteString -> Maybe a

-- data Cryption = forall k e d.
--    Cryption
--   { initial :: forall m. (C.MonadRandom m) => m (e, d)
--   , advance :: e -> e
--   , encrypt :: e -> BL.ByteString -> BL.ByteString
--   , decrypt :: d -> BL.ByteString -> Maybe BL.ByteString
--   }

-- | Encryption method.
class Encryption (e :: Symbol) where
   -- | Key used for encryption. You can obtain an initial random 'Key' using
   -- 'genKey'. As long as you have access to said 'Key', you will be able to
   -- decrypt data previously encrypted with it. For this reason, be sure to
   -- save and load the key using 'dumpKey' and 'loadKey'.
   data Key e :: Type

   -- | Statically known 'Key' length.
   type KeyLength e :: Natural

   -- | Encryption context used by 'encrypt'.
   data Encrypt e :: Type

   -- | Decryption context used by 'decrypt'.
   data Decrypt e :: Type

   -- | Generate a random encryption 'Key'.
   genKey :: (C.MonadRandom m) => m (Key e)

   -- | Load a 'Key' from raw bytes, if possible.
   loadKey :: (BA.ByteArrayAccess raw) => raw -> Maybe (Key e)

   -- | Dump the raw bytes of a 'Key'.
   dumpKey :: (BAS.ByteArrayN (KeyLength e) raw) => Key e -> raw

   -- | Generate initial 'Encrypt'ion and 'Decrypt'ion context for a 'Key'.
   --
   -- The 'Encrypt'ion context could carry for example the next nonce to use
   -- for 'encrypt'ion, the 'Key' itself or its derivative used during the
   -- actual 'encrypt'ion process, or a deterministic random number generator.
   --
   -- The 'Decrypt'ion context could carry for example the 'Key' itself or its
   -- derivative used during the 'decrypt'ion process.
   initial :: (C.MonadRandom m) => Key e -> m (Encrypt e, Decrypt e)

   -- | After each 'encrypt'ion, the 'Encrypt'ion context will be automatically
   -- 'advance'd through this function. For example, if your 'Encrypt'ion
   -- context carries a nonce or a deterministic random number generator,
   -- this is the place to update them.
   advance :: Encrypt e -> Encrypt e

   -- | Encrypt a plaintext message according to the 'Encrypt'ion context.
   encrypt :: Encrypt e -> BL.ByteString -> BL.ByteString

   -- | Decrypt a message according to the 'Decrypt'ion context.
   decrypt :: Decrypt e -> BL.ByteString -> Maybe BL.ByteString

data Config (c :: Symbol) (e :: Symbol) (a :: Type) = Config
   { key :: Key e
   , setCookie :: SetCookie
   }

-- | Read-write access to the 'middleware' session data.
--
-- See 'sessionRequestData', 'sessionDeleteOnResponse',
-- 'sessionSetOnResponse'.
data Session a = Session (Maybe a) (TVar (Maybe (Maybe a)))

-- | The session data that came through the 'Wai.Request' cookie, if any.
sessionRequestData :: Session a -> Maybe a
sessionRequestData (Session x _) = x

-- | Cause the next 'Wai.Response' to set the session cookie to the
-- specified value.
--
-- Overrides previous uses of 'sessionSetOnResponse' and
-- 'sessionDeleteOnResponse'.
sessionSetOnResponse :: Session a -> a -> STM ()
sessionSetOnResponse (Session _ x) = writeTVar x . Just . Just

-- | Cause the next 'Wai.Response' to delete session cookie.
--
-- Overrides previous uses of 'sessionSetOnResponse' and
-- 'sessionDeleteOnResponse'.
sessionDeleteOnResponse :: Session a -> STM ()
sessionDeleteOnResponse (Session _ x) = writeTVar x $ Just Nothing

middleware
   :: forall m c e a
    . (MonadIO m, Codec c a, Encryption e)
   => Config c e a
   -- ^ Consider using 'Wai.SessionCookie.defaultConfig'.
   -> m (V.Key (Session a), Wai.Middleware)
middleware c = liftIO do
   (mec :: IO (Encrypt e), dc :: Decrypt e) <- do
      (!ec0, !dc) <- initial c.key
      ecRef <- newIORef ec0
      pure (atomicModifyIORef' ecRef \ec -> (advance ec, ec), dc)
   vk :: V.Key (Session a) <- V.newKey
   pure $ (,) vk \app req0 respond -> do
      let ya0 = getRequestSessionData c dc req0
      tv <- newTVarIO Nothing
      app
         (req0{Wai.vault = V.insert vk (Session ya0 tv) (Wai.vault req0)})
         \res -> do
            yya1 <- readTVarIO tv
            let f = case yya1 of
                  Nothing -> pure
                  Just Nothing -> expireResponseSessionData c
                  Just (Just a1) -> setResponseSessionData c mec a1
            respond =<< f res

-- | Find, decrypt and decode the session value from the 'Wai.Request'.
--
-- 'Nothing' if the unique session cookie couldn't be found
-- or couldn't be decrypted. 'Left' if the 'Codec' failed.
getRequestSessionData
   :: forall c e a
    . (Codec c a, Encryption e)
   => Config c e a
   -> Decrypt e
   -> Wai.Request
   -> Maybe a
getRequestSessionData c d r = do
   let cookieName = setCookieName c.setCookie
   [cry64] <- pure $ lookupMany cookieName $ requestCookies r
   cry <- either (const Nothing) Just do
      BA.convertFromBase BA.Base64URLUnpadded cry64
   decode (Proxy @c) =<< decrypt d (B.fromStrict cry)

-- | Adds the @Set-Cookie@ header to the 'Wai.Response'.
setResponseSessionData
   :: forall m c e a
    . (MonadFail m, Codec c a, Encryption e)
   => Config c e a
   -> m (Encrypt e)
   -> a
   -> Wai.Response
   -> m Wai.Response
setResponseSessionData c = \mec a res ->
   case find predicate (responseCookies res) of
      Nothing | !enc <- encode (Proxy @c) a -> do
         ec <- mec
         let raw = B.toStrict $ encrypt ec enc
             raw64 = BA.convertToBase BA.Base64URLUnpadded raw
             hval = renderSetCookieBS $ c.setCookie{setCookieValue = raw64}
         pure $ Wai.mapResponseHeaders (("Set-Cookie", hval) :) res
      _ -> fail $ "Duplicate cookie name: " <> show cookieName
  where
   cookieName = setCookieName c.setCookie
   predicate = \x -> setCookieName x == cookieName

-- | Adds the @Set-Cookie@ header to the 'Wai.Response'.
expireResponseSessionData
   :: forall m c e a
    . (MonadFail m)
   => Config c e a
   -> Wai.Response
   -> m Wai.Response
expireResponseSessionData c = \res ->
   case find predicate (responseCookies res) of
      Nothing -> pure $ Wai.mapResponseHeaders (("Set-Cookie", hval) :) res
      _ -> fail $ "Duplicate cookie name: " <> show cookieName
  where
   cookieName = setCookieName c.setCookie
   predicate = \x -> setCookieName x == cookieName
   hval =
      renderSetCookieBS $
         c.setCookie
            { setCookieValue = mempty
            , setCookieExpires = Just (Time.posixSecondsToUTCTime 0)
            , setCookieMaxAge = Just (negate 1)
            }

--------------------------------------------------------------------------------

requestCookies :: Wai.Request -> [(B.ByteString, B.ByteString)]
requestCookies r = parseCookies =<< lookupMany "Cookie" (Wai.requestHeaders r)

responseCookies :: Wai.Response -> [SetCookie]
responseCookies =
   fmap parseSetCookie . lookupMany "Set-Cookie" . Wai.responseHeaders

--------------------------------------------------------------------------------

lookupMany :: (Eq k) => k -> [(k, v)] -> [v]
lookupMany k = findMany (== k)

findMany :: (Eq k) => (k -> Bool) -> [(k, v)] -> [v]
findMany f = map snd . filter (\(a, _) -> f a)
