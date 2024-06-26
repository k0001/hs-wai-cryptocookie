{-# LANGUAGE StrictData #-}
{-# LANGUAGE NoFieldSelectors #-}

module Wai.CryptoCookie.Middleware
   ( Config (..)
   , CryptoCookie
   , get
   , set
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
         , decrypt = either (const Nothing) Just . decrypt dc
         , encoding
         , setCookie
         }

-- | Read-write access to the "Wai.CryptoCookie" data.
--
-- See 'get' and 'set'.
data CryptoCookie a = CryptoCookie (Maybe a) (TVar (Maybe (Maybe a)))

-- | The data that came through the 'Wai.Request' cookie, if any.
get :: CryptoCookie a -> Maybe a
get (CryptoCookie x _) = x

-- | Cause the eventual 'Wai.Response' corresponding to the current
-- 'Wai.Request' to set the cookie to the specified value if 'Just', or expire
-- (/delete/) the cookie if 'Nothing'.
--
-- Overrides previous uses of 'set'.
set :: CryptoCookie a -> Maybe a -> STM ()
set (CryptoCookie _ x) = writeTVar x . Just

-- | Obtain a new 'Wai.Application'-transforming function (more or less a
-- 'Wai.Middleware') wherein the 'Wai.Application' being transformed can interact
-- with a 'CryptoCookie'.
--
-- * 'middleware' can be called multiple times as long as the 'setCookieName'
-- for the 'SetCookie' specified in 'Config' is different each time.
--
-- * It is safe to reuse the same 'Key' for multiple 'middleware' calls.  Each
-- time the 'Key' will have a different randomly 'initial'ized 'Encrypt'ion
-- context.
middleware
   :: forall a m
    . (MonadIO m)
   => Config a
   -- ^ Consider using 'Wai.CryptoCookie.defaultConfig'.
   -> m ((CryptoCookie a -> Wai.Application) -> Wai.Application)
   -- ^ Remember that 'Wai.Middleware' is a type-synonym for
   -- @'Wai.Application' -> 'Wai.Application'@.  This type is not too different
   -- from that.
middleware c = liftIO do
   env <- newEnv c
   pure \fapp -> \req respond -> do
      tv <- newTVarIO Nothing
      fapp (CryptoCookie (getRequestCookieData env req) tv) req \res -> do
         yya1 <- readTVarIO tv
         let f = case yya1 of
               Nothing -> pure
               Just Nothing -> expireResponseCookieData env
               Just (Just a1) -> setResponseCookieData env a1
         respond =<< f res

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
