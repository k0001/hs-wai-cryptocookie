{-# LANGUAGE StrictData #-}
{-# LANGUAGE NoFieldSelectors #-}

module Wai.CryptoCookie.Middleware
   ( Config (..)
   , CryptoCookie
   , get
   , set
   , delete
   , middleware
   ) where

import Control.Concurrent.STM
import Control.Monad.IO.Class
import Data.ByteArray.Encoding qualified as BA
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as BL
import Data.IORef
import Data.Kind (Type)
import Data.List (find)
import Data.Time.Clock.POSIX qualified as Time
import Data.Vault.Lazy qualified as V
import Network.Wai qualified as Wai
import Web.Cookie
   ( SetCookie (..)
   , parseCookies
   , parseSetCookie
   , renderSetCookieBS
   )

import Wai.CryptoCookie.Encoding (Encoding (..))
import Wai.CryptoCookie.Encryption (Encryption (..))

-- | Configuration for 'middleware'.
--
-- Consider using 'Wai.CryptoCookie.defaultConfig' and
-- updating desired fields only.
data Config (a :: Type) = forall e.
    (Encryption e) =>
   Config
   { key :: Key e
   , encoding :: Encoding a
   , setCookie :: SetCookie
   }

data Env (a :: Type) = Env
   { encrypt :: BL.ByteString -> IO BL.ByteString
   , decrypt :: BL.ByteString -> Maybe BL.ByteString
   , encoding :: Encoding a
   , setCookie :: SetCookie
   }

encodeEncrypt :: Env a -> a -> IO B.ByteString
encodeEncrypt env a = do
   cryl <- env.encrypt $! env.encoding.encode a
   pure $ BA.convertToBase BA.Base64URLUnpadded $ BL.toStrict cryl

decryptDecode :: Env a -> B.ByteString -> Maybe a
decryptDecode env cry64 = do
   cry <- either (const Nothing) Just do
      BA.convertFromBase BA.Base64URLUnpadded cry64
   env.encoding.decode =<< env.decrypt (B.fromStrict cry)

newEnv :: Config a -> IO (Env a)
newEnv Config{key, encoding, setCookie} = do
   (!ec0, !dc) <- initial key
   ecRef <- newIORef ec0
   pure
      Env
         { encrypt = \raw -> do
            ec <- atomicModifyIORef' ecRef \ec -> (advance ec, ec)
            pure $ encrypt ec raw
         , decrypt = decrypt dc
         , encoding
         , setCookie
         }

-- | Read-write access to the "Wai.CryptoCookie" data.
--
-- See 'get', 'delete', 'set'.
data CryptoCookie a = CryptoCookie (Maybe a) (TVar (Maybe (Maybe a)))

-- | The data that came through the 'Wai.Request' cookie, if any.
get :: CryptoCookie a -> Maybe a
get (CryptoCookie x _) = x

-- | Cause the next 'Wai.Response' to set the cookie to the specified value.
--
-- Overrides previous uses of 'set' and 'delete'.
set :: CryptoCookie a -> a -> STM ()
set (CryptoCookie _ x) = writeTVar x . Just . Just

-- | Cause the next 'Wai.Response' to delete the cookie.
--
-- Overrides previous uses of 'set' and 'delete'.
delete :: CryptoCookie a -> STM ()
delete (CryptoCookie _ x) = writeTVar x $ Just Nothing

-- | Construct a new 'Middleware', and function that can be used to look-up the
-- 'CryptoCookie' on each incoming 'Wai.Request'. Said function returns
-- 'Nothing' if the 'Middleware' was not used on the 'Wai.Request'.
middleware
   :: forall a m
    . (MonadIO m)
   => Config a
   -- ^ Consider using 'Wai.CryptoCookie.defaultConfig'.
   -> m (Wai.Middleware, Wai.Request -> Maybe (CryptoCookie a))
middleware c = liftIO do
   env <- newEnv c
   vk :: V.Key (CryptoCookie a) <- V.newKey
   pure
      ( \app req respond -> do
         tv <- newTVarIO Nothing
         let ck = CryptoCookie (getRequestCookieData env req) tv
         app (req{Wai.vault = V.insert vk ck (Wai.vault req)}) \res -> do
            yya1 <- readTVarIO tv
            let f = case yya1 of
                  Nothing -> pure
                  Just Nothing -> expireResponseCookieData env
                  Just (Just a1) -> setResponseCookieData env a1
            respond =<< f res
      , \req -> V.lookup vk (Wai.vault req)
      )

-- | Find, decrypt and decode the cookie value from the 'Wai.Request'.
--
-- 'Nothing' if the unique cookie couldn't be found
-- or couldn't be decrypted. 'Left' if the 'Encoding' failed.
getRequestCookieData :: Env a -> Wai.Request -> Maybe a
getRequestCookieData env r = do
   let cookieName = setCookieName env.setCookie
   [cry] <- pure $ lookupMany cookieName $ requestCookies r
   decryptDecode env cry

-- | Adds the @Set-Cookie@ header to the 'Wai.Response'.
setResponseCookieData :: Env a -> a -> Wai.Response -> IO Wai.Response
setResponseCookieData env a = \res ->
   case find predicate (responseCookies res) of
      Nothing -> do
         cry <- encodeEncrypt env a
         let hval = renderSetCookieBS $ env.setCookie{setCookieValue = cry}
         pure $ Wai.mapResponseHeaders (("Set-Cookie", hval) :) res
      _ -> fail $ "Duplicate cookie name: " <> show cookieName
  where
   cookieName = setCookieName env.setCookie
   predicate = \x -> setCookieName x == cookieName

-- | Adds the @Set-Cookie@ header to the 'Wai.Response'.
expireResponseCookieData :: Env a -> Wai.Response -> IO Wai.Response
expireResponseCookieData env = \res ->
   case find predicate (responseCookies res) of
      Nothing -> pure $ Wai.mapResponseHeaders (("Set-Cookie", hval) :) res
      _ -> fail $ "Duplicate cookie name: " <> show cookieName
  where
   cookieName = setCookieName env.setCookie
   predicate = \x -> setCookieName x == cookieName
   hval =
      renderSetCookieBS $
         env.setCookie
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
