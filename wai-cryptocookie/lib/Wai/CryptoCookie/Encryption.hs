{-# LANGUAGE StrictData #-}
{-# LANGUAGE NoFieldSelectors #-}

-- | You will need to import this module if you are planning to define an
-- 'Encryption' scheme other than the defaults provided by this library.
module Wai.CryptoCookie.Encryption
   ( Encryption (..)
   , autoKeyFileBase16
   , readKeyFileBase16
   , readKeyFile
   , writeKeyFile
   ) where

import Control.Exception qualified as Ex
import Control.Monad
import Control.Monad.IO.Class
import Crypto.Random qualified as C
import Data.Aeson qualified as Ae
import Data.Bits
import Data.ByteArray qualified as BA
import Data.ByteArray.Encoding qualified as BA
import Data.ByteArray.Parse qualified as BAP
import Data.ByteArray.Sized qualified as BAS
import Data.ByteString.Lazy qualified as BL
import Data.Char qualified as Char
import Data.Kind (Type)
import Data.Text.Encoding qualified as T
import Data.Word
import GHC.TypeNats
import System.IO qualified as IO
import System.IO.Error qualified as IO

-- | Encryption method.
class (KnownNat (KeyLength e), Eq (Key e)) => Encryption (e :: k) where
   -- | Key used for encryption. You can obtain an initial random
   -- 'Key' using 'genKey'. As long as you have access to
   -- said 'Key', you will be able to decrypt data previously
   -- encrypted with it. For this reason, be sure to save and load the key
   -- using 'keyToBytes' and 'keyFromBytes'.
   data Key e :: Type

   -- | Statically known 'Key' length.
   type KeyLength e :: Natural

   -- | Encryption context used by 'encrypt'.
   data Encrypt e :: Type

   -- | Decryption context used by 'decrypt'.
   data Decrypt e :: Type

   -- | Generate a random encryption 'Key'.
   genKey :: (C.MonadRandom m) => m (Key e)

   -- | Load a 'Key' from its bytes representation, if possible.
   keyFromBytes :: (BA.ByteArrayAccess raw) => raw -> Maybe (Key e)

   -- | Dump the bytes representation of a 'Key'.
   keyToBytes :: (BAS.ByteArrayN (KeyLength e) raw) => Key e -> raw

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

-- | If the 'FilePath' exists, then read the base-16 representation of
-- a 'Key' from it. Ignores trailing newlines.
--
-- Otherwise, generate a random new 'Key' and write its base-16 representation
-- in the 'FilePath'.
--
-- Finally, return the 'Key'.
autoKeyFileBase16
   :: forall e m
    . (Encryption e, MonadIO m)
   => FilePath
   -> m (Key e)
autoKeyFileBase16 path = liftIO do
   Ex.catchJust
      (guard . IO.isDoesNotExistError)
      (readKeyFileBase16 path)
      \_ -> do
         k0 <- genKey
         writeKeyFile (BA.convertToBase BA.Base16) path k0
         k1 <- readKeyFileBase16 path
         when (k0 /= k1) $ fail "autoKeyFile: no roundtrip"
         pure k1

-- | Read a base-16 encoded 'Key' from a file. Ignores trailing newlines.
readKeyFileBase16
   :: forall e m
    . (Encryption e, MonadIO m)
   => FilePath
   -> m (Key e)
readKeyFileBase16 = readKeyFile \a -> case BAP.parse p a of
   BAP.ParseOK _ b -> BA.convertFromBase BA.Base16 b
   _ -> Left "can't parse key"
  where
   p :: BAP.Parser BA.ScrubbedBytes BA.ScrubbedBytes
   p = do
      -- We optionally skip trailing newlines.
      let rn = \w -> w == _r || w == _n
      x <- BAP.takeWhile (not . rn)
      BAP.skipWhile rn
      False <- BAP.hasMore
      pure x
   _r :: Word8 = fromIntegral (Char.ord '\r')
   _n :: Word8 = fromIntegral (Char.ord '\n')

-- | Read a 'Key' from a file.
readKeyFile
   :: forall e m
    . (Encryption e, MonadIO m)
   => (BA.ScrubbedBytes -> Either String BA.ScrubbedBytes)
   -- ^ Convert the raw content of the file into input suitable
   -- for 'keyFromBytes'.
   -> FilePath
   -> m (Key e)
readKeyFile g path = liftIO do
   IO.withFile path IO.ReadMode \h -> do
      flen :: Int <- do
         a <- IO.hFileSize h
         case toIntegralSized a of
            Just b | b > 0 -> pure b
            _ -> fail "readKeyFile: invalid key file size"
      (rlen, fraw) <- BA.allocRet flen \p -> IO.hGetBuf h p flen
      when (rlen /= flen) do
         -- This shouldn't happen, but we are being extra careful.
         fail "readKeyFile: could not read key file"
      case g fraw of
         Left e -> fail $ "readKeyFile: " <> e
         Right kraw
            | Just key <- keyFromBytes kraw -> pure key
            | otherwise -> fail "readKeyFile: invalid key"

-- | Save a key to a file.
writeKeyFile
   :: forall e m
    . (Encryption e, MonadIO m)
   => (BAS.SizedByteArray (KeyLength e) BA.ScrubbedBytes -> BA.ScrubbedBytes)
   -- ^ Convert the raw 'keyToBytes' bytes to file contents.
   -> FilePath
   -> Key e
   -> m ()
writeKeyFile g path key = liftIO do
   kraw <- Ex.evaluate $ g $ keyToBytes key
   IO.withFile path IO.WriteMode \h ->
      BA.withByteArray kraw \p ->
         IO.hPutBuf h p $ BA.length kraw

-- | Base-16 encoded.
instance Encryption e => Ae.FromJSON (Key e) where
   parseJSON = Ae.withText "Key" \t ->
      -- Note that un-scrubbable bytes will continue to exist in @t@.
      case BA.convertFromBase BA.Base16 (T.encodeUtf8 t) of
         Right (kraw :: BA.ScrubbedBytes)
            | Just key <- keyFromBytes kraw -> pure key
         _ -> fail "Invalid key"