module Main (main) where

import Control.Exception qualified as Ex
import Control.Monad
import Network.Wai qualified as W
import System.Directory
import System.FilePath
import System.IO.Error (isAlreadyExistsError)

import Wai.CryptoCookie qualified as WCC

main :: IO ()
main = withTmpDir \tmp -> do
   let k1path = tmp </> "key1"
   k1a <- WCC.autoKeyFileBase16 @"AEAD_AES_256_GCM_SIV" k1path
   k1b <- WCC.autoKeyFileBase16 @"AEAD_AES_256_GCM_SIV" k1path
   when (k1a /= k1b) $ fail "k1a /= k1b"
   k1c <- WCC.readKeyFileBase16 @"AEAD_AES_256_GCM_SIV" k1path
   when (k1a /= k1c) $ fail "k1a /= k1c"
   let c1 = WCC.defaultConfig k1a
   (mw1, look1) <- WCC.middleware c1



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
