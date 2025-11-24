{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Exception qualified as Ex
import Control.Monad
import Control.Monad.IO.Class
import Data.Aeson qualified as Ae
import Data.Binary qualified as Bin
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as BL
import Data.Maybe
import Data.Proxy
import Data.String
import Data.Text qualified as T
import GHC.TypeLits (natVal)
import Network.HTTP.Types qualified as HT
import Network.Wai qualified as W
import Network.Wai.Test qualified as WT
import System.Directory
import System.FilePath
import System.IO.Error (isAlreadyExistsError)
import Web.Cookie qualified as WC

import Wai.CryptoCookie qualified as WCC

main :: IO ()
main = withTmpDir \tmp -> do
   let k1path = tmp </> "key1"
   k1a <- WCC.autoKeyFileBase16 @"AEAD_AES_256_GCM_SIV" k1path
   k1b <- WCC.autoKeyFileBase16 @"AEAD_AES_256_GCM_SIV" k1path
   when (k1a /= k1b) $ fail "k1a /= k1b"
   k1c <- WCC.readKeyFileBase16 @"AEAD_AES_256_GCM_SIV" k1path
   when (k1a /= k1c) $ fail "k1a /= k1c"

   testEncryption @"AEAD_AES_256_GCM_SIV" k1a
   testEncryption @"AEAD_AES_256_GCM_SIV" =<< WCC.randomKey
   testEncryption @"AEAD_AES_128_GCM_SIV" =<< WCC.randomKey
   testCookies @"AEAD_AES_256_GCM_SIV" =<< WCC.randomKey
   testCookies @"AEAD_AES_128_GCM_SIV" =<< WCC.randomKey

   testBase16Load
   testBase16Roundtrip k1a

   testAesonLoad
   testAesonRoundtrip k1a

   testBinaryLoad
   testBinaryRoundtrip k1a

   putStrLn "TESTS OK"

testBase16Roundtrip :: forall e. (WCC.Encryption e) => WCC.Key e -> IO ()
testBase16Roundtrip k = do
   let kBase16 = WCC.keyToBase16Text k
       rawLen = fromInteger $ natVal $ Proxy @(WCC.KeyLength e)
   when (T.length kBase16 /= 2 * rawLen) do
      fail "testBase16Roundtrip: unexpected length"
   case WCC.keyFromBase16Text kBase16 of
      Left e -> fail ("testBase16Roundtrip: " <> show e)
      Right k2
         | k /= k2 -> fail "testBase16Roundtrip: no roundtrip"
         | otherwise -> pure ()

testBase16Load :: IO ()
testBase16Load = do
   let kBase16 = "7aa382cffa3715609cdc6f782fc44d6c0f854e2b35641ddfd9173e427c418ec8"
   case WCC.keyFromBase16Text kBase16 of
      Left e -> fail ("testBase16Load: " <> show e)
      Right k
         | WCC.keyToBase16Text k /= kBase16 -> fail "testBase16Load: no roundtrip"
         | otherwise -> testEncryption @"AEAD_AES_256_GCM_SIV" k

testAesonRoundtrip :: forall e. (WCC.Encryption e) => WCC.Key e -> IO ()
testAesonRoundtrip k = do
   let kJSON = Ae.encode k
       rawLen = fromInteger $ natVal $ Proxy @(WCC.KeyLength e)
   when (BL.length kJSON /= 2 + 2 * rawLen) do
      fail "testAesonRoundtrip: unexpected length"
   case Ae.eitherDecode kJSON of
      Left e -> fail ("testAesonRoundtrip: " <> show e)
      Right k2
         | k /= k2 -> fail "testAesonRoundtrip: no roundtrip"
         | otherwise -> pure ()

testAesonLoad :: IO ()
testAesonLoad = do
   let kJSON = "\"7aa382cffa3715609cdc6f782fc44d6c0f854e2b35641ddfd9173e427c418ec8\""
   case Ae.eitherDecode kJSON of
      Left e -> fail ("testAesonLoad: " <> show e)
      Right k
         | Ae.encode k /= kJSON -> fail "testAesonLoad: no roundtrip"
         | otherwise -> testEncryption @"AEAD_AES_256_GCM_SIV" k

testBinaryRoundtrip :: forall e. (WCC.Encryption e) => WCC.Key e -> IO ()
testBinaryRoundtrip k = do
   let kBin = Ae.encode k
       rawLen = fromInteger $ natVal $ Proxy @(WCC.KeyLength e)
   when (BL.length kBin /= 2 + 2 * rawLen) do
      fail "testBinaryRoundtrip: unexpected length"
   case Ae.eitherDecode kBin of
      Left e -> fail ("testBinaryRoundtrip: " <> show e)
      Right k2
         | k /= k2 -> fail "testBinaryRoundtrip: no roundtrip"
         | otherwise -> pure ()

testBinaryLoad :: IO ()
testBinaryLoad = do
   let kBin = "_a_right_amount_of_sample_bytes_"
   case Bin.decodeOrFail kBin of
      Left (_, _, e) -> fail ("testBinaryLoad: " <> show e)
      Right (lo, _, k)
         | not (BL.null lo) -> fail "testBinaryLoad: leftovers"
         | Bin.encode k /= kBin -> fail "testBinaryLoad: no roundtrip"
         | otherwise -> testEncryption @"AEAD_AES_256_GCM_SIV" k

testEncryption :: (WCC.Encryption e) => WCC.Key e -> IO ()
testEncryption key = do
   e0a <- do
      s0 <- WCC.initEncrypt key
      let de = WCC.initDecrypt key
      either fail pure do
         let r0 = ""
         let e0 = WCC.encrypt s0 "a" r0
         when (r0 == e0) $ Left "e0"
         r0' <- WCC.decrypt de "a" e0
         when (r0 /= r0') $ Left "r0'"
         let s1 = WCC.advance s0
         let e0' = WCC.encrypt s1 "b" r0
         when (e0 == e0') $ Left "e0'"
         r0'' <- WCC.decrypt de "b" e0'
         when (r0 /= r0'') $ Left "r0''"
         let r1 = "hello"
         let s2 = WCC.advance s1
         let e1 = WCC.encrypt s2 "" r1
         when (r1 == e1) $ Left "e1"
         r1' <- WCC.decrypt de "" e1
         when (r1 /= r1') $ Left "r1'"
         let s3 = WCC.advance s2
         let e1' = WCC.encrypt s3 "boo" r1
         when (e1 == e1') $ Left "e1'"
         r1'' <- WCC.decrypt de "boo" e1'
         when (r1 /= r1'') $ Left "r1''"
         pure e0

   e0b <- do
      s0 <- WCC.initEncrypt key
      let de = WCC.initDecrypt key
      either fail pure do
         let r0 = ""
         let e0 = WCC.encrypt s0 "aa" r0
         pure e0

   when (e0a == e0b) $ fail "e0b"

testCookies :: (WCC.Encryption e) => WCC.Key e -> IO ()
testCookies k = do
   env :: WCC.Env () Word <- do
      c0 <- WCC.defaultConfig <$> WCC.randomKey
      WCC.newEnv c0{WCC.key = k, WCC.aadEncode = \() -> "hello"}

   let fapp1 :: (Maybe Word -> Maybe (Maybe Word)) -> W.Application
       fapp1 = \g -> WCC.middleware env (app1 env g . join . fmap snd) (Just ())

   -- keeping cookies untouched
   WT.withSession (fapp1 \_ -> Nothing) do
      WT.assertNoClientCookieExists "t0-a" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertNoClientCookieExists "t0-b" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertNoClientCookieExists "t0-c" "SESSION"

   -- explicitly deleting cookie
   WT.withSession (fapp1 \_ -> Just Nothing) do
      WT.assertNoClientCookieExists "t1-a" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t1-b" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t1-c" "SESSION"

   -- explicitely setting cookie
   ck0 <- WT.withSession (fapp1 \_ -> Just (Just 900)) do
      WT.assertNoClientCookieExists "t2-a" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t2-b" "SESSION"
      sres2 <- WT.request WT.defaultRequest
      WT.assertBody "Just 900" sres2
      WT.assertClientCookieExists "t2-c" "SESSION"
      WT.getClientCookies

   -- modify and explicitly delete
   WT.withSession (fapp1 \_ -> Just Nothing) do
      WT.assertNoClientCookieExists "t3-a" "SESSION"
      WT.modifyClientCookies \_ -> ck0
      WT.assertClientCookieExists "t3-b" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Just 900" sres1
      WT.assertClientCookieExists "t3-c" "SESSION"
      sres2 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres2
      WT.assertClientCookieExists "t3-d" "SESSION"
      WT.assertClientCookieValue "t3-e" "SESSION" ""

   -- set/modify
   WT.withSession (fapp1 (Just . fmap (+ 1))) do
      WT.assertNoClientCookieExists "t4-a" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t4-b" "SESSION"
      WT.modifyClientCookies \_ -> ck0
      WT.assertClientCookieExists "t4-c" "SESSION"
      sres2 <- WT.request WT.defaultRequest
      WT.assertBody "Just 900" sres2
      WT.assertClientCookieExists "t4-d" "SESSION"
      sres2 <- WT.request WT.defaultRequest
      WT.assertBody "Just 901" sres2
      WT.assertClientCookieExists "t4-c" "SESSION"

app1
   :: WCC.Env () Word
   -> (Maybe Word -> Maybe (Maybe Word))
   -> Maybe Word
   -> W.Application
app1 env g yold = \req respond -> do
   ysc :: Maybe WC.SetCookie <- case g yold of
      Nothing -> pure Nothing
      Just Nothing -> pure $ Just $ WCC.expireCookie env
      Just (Just new) -> Just <$> WCC.setCookie env () new
   respond
      $ W.responseLBS
         HT.status200
         ( fmap
            (\sc -> ("Set-Cookie", WC.renderSetCookieBS sc))
            (maybeToList ysc)
         )
      $ fromString (show yold)

withTmpDir :: (FilePath -> IO a) -> IO a
withTmpDir f = do
   tmp0 <- getTemporaryDirectory
   Ex.bracket (acq tmp0 0) (removeDirectoryRecursive) f
  where
   acq :: FilePath -> Word -> IO FilePath
   acq prefix !n = do
      let d1 = prefix </> ("wai-cryptocookie." <> show n)
      Ex.catchJust
         (guard . isAlreadyExistsError)
         (d1 <$ createDirectory d1)
         (\_ -> acq prefix (n + 1))
