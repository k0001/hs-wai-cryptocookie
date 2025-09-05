{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Concurrent.STM
import Control.Exception qualified as Ex
import Control.Monad
import Control.Monad.IO.Class
import Data.String
import Network.HTTP.Types qualified as HT
import Network.Wai qualified as W
import Network.Wai.Test qualified as WT
import System.Directory
import System.FilePath
import System.IO.Error (isAlreadyExistsError)
import System.Random qualified as R

import Wai.CryptoCookie qualified as WCC
import Wai.CryptoCookie.Encryption qualified as WCC

main :: IO ()
main = withTmpDir \tmp -> do
   let k1path = tmp </> "key1"
   k1a <- WCC.autoKeyFileBase16 @"AEAD_AES_256_GCM_SIV" k1path
   k1b <- WCC.autoKeyFileBase16 @"AEAD_AES_256_GCM_SIV" k1path
   when (k1a /= k1b) $ fail "k1a /= k1b"
   k1c <- WCC.readKeyFileBase16 @"AEAD_AES_256_GCM_SIV" k1path
   when (k1a /= k1c) $ fail "k1a /= k1c"
   testEncryption @"AEAD_AES_256_GCM_SIV" k1a
   testEncryption @"AEAD_AES_256_GCM_SIV" =<< WCC.genKey
   testEncryption @"AEAD_AES_128_GCM_SIV" =<< WCC.genKey
   testCookies @"AEAD_AES_256_GCM_SIV" =<< WCC.genKey
   testCookies @"AEAD_AES_128_GCM_SIV" =<< WCC.genKey
   putStrLn "TESTS OK"

testEncryption :: (WCC.Encryption e) => WCC.Key e -> IO ()
testEncryption key = do
   e0a <- do
      (s0, de) <- WCC.initial key
      either fail pure do
         let r0 = ""
         let e0 = WCC.encrypt s0 r0
         when (r0 == e0) $ Left "e0"
         r0' <- WCC.decrypt de e0
         when (r0 /= r0') $ Left "r0'"
         let s1 = WCC.advance s0
         let e0' = WCC.encrypt s1 r0
         when (e0 == e0') $ Left "e0'"
         r0'' <- WCC.decrypt de e0'
         when (r0 /= r0'') $ Left "r0''"
         let r1 = "hello"
         let s2 = WCC.advance s1
         let e1 = WCC.encrypt s2 r1
         when (r1 == e1) $ Left "e1"
         r1' <- WCC.decrypt de e1
         when (r1 /= r1') $ Left "r1'"
         let s3 = WCC.advance s2
         let e1' = WCC.encrypt s3 r1
         when (e1 == e1') $ Left "e1'"
         r1'' <- WCC.decrypt de e1'
         when (r1 /= r1'') $ Left "r1''"
         pure e0

   e0b <- do
      (s0, de) <- WCC.initial key
      either fail pure do
         let r0 = ""
         let e0 = WCC.encrypt s0 r0
         pure e0

   when (e0a == e0b) $ fail "e0b"

testCookies :: (WCC.Encryption e) => WCC.Key e -> IO ()
testCookies k = do
   c1 <- do
      c <- fmap WCC.defaultConfig WCC.genKey
      pure c{WCC.key = k}
   fmw1 <- WCC.middleware c1

   -- keeping cookies untouched
   WT.withSession (fmw1 $ app \_ -> Nothing) do
      WT.assertNoClientCookieExists "t0-a" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertNoClientCookieExists "t0-b" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertNoClientCookieExists "t0-c" "SESSION"

   -- explicitly deleting cookie
   WT.withSession (fmw1 $ app \_ -> Just Nothing) do
      WT.assertNoClientCookieExists "t1-a" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t1-b" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t1-c" "SESSION"

   -- explicitely setting cookie
   ck0 <- WT.withSession (fmw1 $ app \_ -> Just (Just 900)) do
      WT.assertNoClientCookieExists "t2-a" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t2-b" "SESSION"
      sres2 <- WT.request WT.defaultRequest
      WT.assertBody "Just 900" sres2
      WT.assertClientCookieExists "t2-c" "SESSION"
      WT.getClientCookies

   -- modify and explicitly delete
   WT.withSession (fmw1 $ app \_ -> Just Nothing) do
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
   WT.withSession (fmw1 $ app (Just . fmap (+ 1))) do
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

   -- We make sure that no matter how many interactions with
   -- cc we have, we always keep the last. See app2.
   WT.withSession (fmw1 app2) do
      WT.assertNoClientCookieExists "t5-a" "SESSION"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      replicateM_ 1000 do
         WT.assertClientCookieExists "t5-b" "SESSION"
         sres1 <- WT.request WT.defaultRequest
         WT.assertBody "Just 2" sres1

app
   :: (Maybe Word -> Maybe (Maybe Word))
   -> WCC.CryptoCookie Word
   -> W.Application
app g cc = \req res -> do
   let yold = WCC.get cc
   case g yold of
      Nothing -> pure ()
      Just Nothing -> atomically $ WCC.delete cc
      Just (Just new) -> atomically $ WCC.set cc new
   res $ W.responseLBS HT.status200 [] $ fromString $ show yold

app2 :: WCC.CryptoCookie Word -> W.Application
app2 cc = \req res -> do
   n <- R.randomRIO (0, 10)
   xs <- replicateM n $ R.randomRIO ('a', 'c')
   forM_ xs \case
      'a' -> atomically $ WCC.set cc 1
      'b' -> atomically $ WCC.delete cc
      _ -> atomically $ WCC.keep cc
   atomically $ WCC.set cc 2
   res $ W.responseLBS HT.status200 [] $ fromString $ show $ WCC.get cc

withTmpDir :: (FilePath -> IO a) -> IO a
withTmpDir f = do
   tmp0 <- getTemporaryDirectory
   Ex.bracket (acq tmp0 0) (\_ -> pure () {-removeDirectoryRecursive-}) f
  where
   acq :: FilePath -> Word -> IO FilePath
   acq prefix !n = do
      let d1 = prefix </> ("wai-cryptocookie." <> show n)
      Ex.catchJust
         (guard . isAlreadyExistsError)
         (d1 <$ createDirectory d1)
         (\_ -> acq prefix (n + 1))
