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
import Data.ByteArray.Sized qualified as BAS
import Data.ByteString.Lazy qualified as BL
import Data.Char qualified as Char
import Data.Kind (Type)
import Data.Text.Encoding qualified as T
import Data.Word
import GHC.TypeNats
import System.IO qualified as IO
import System.IO.Error qualified as IO

-- | AEAD encryption method.
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
   randomKey :: (C.MonadRandom m) => m (Key e)

   -- | Load a 'Key' from its bytes representation, if possible.
   keyFromBytes :: (BA.ByteArrayAccess raw) => raw -> Either String (Key e)

   -- | Dump the bytes representation of a 'Key'.
   keyToBytes :: (BAS.ByteArrayN (KeyLength e) raw) => Key e -> raw

   -- | Generate initial 'Encrypt'ion context for a 'Key'.
   --
   -- The 'Encrypt'ion context could carry for example the next
   -- __randomly generated nonce__ to use for 'encrypt'ion, the 'Key'
   -- itself or its derivative used during the actual 'encrypt'ion
   -- process, or a deterministic random number generator.
   --
   -- The 'Decrypt'ion context could carry for example the 'Key' itself or its
   -- derivative used during the 'decrypt'ion process.
   initEncrypt :: (C.MonadRandom m) => Key e -> m (Encrypt e)

   -- | Generate initial 'Decrypt'ion context for a 'Key'.
   --
   -- The 'Decrypt'ion context could carry for example the 'Key' itself or its
   -- derivative used during the 'decrypt'ion process.
   initDecrypt :: Key e -> Decrypt e

   -- | After each 'encrypt'ion, the 'Encrypt'ion context will be automatically
   -- 'advance'd through this function. For example, if your 'Encrypt'ion
   -- context carries a nonce or a deterministic random number generator,
   -- this is the place to update them.
   advance :: Encrypt e -> Encrypt e

   -- | Encrypt a plaintext message according to the 'Encrypt'ion context.
   encrypt
      :: Encrypt e
      -> BL.ByteString
      -- ^ AEAD associated data.
      -> BL.ByteString
      -- ^ Message to encrypt.
      -> BL.ByteString
      -- ^ Encrypted message including AEAD tag and nonce.

   -- | Decrypt a message according to the 'Decrypt'ion context.
   --
   -- The 'String' is for internal debugging purposes only.
   decrypt
      :: Decrypt e
      -> BL.ByteString
      -- ^ AEAD associated data.
      -> BL.ByteString
      -- ^ Encrypted message including AEAD tag and nonce.
      -> Either String BL.ByteString
      -- ^ Decrypted message or error message.

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
         k0 <- randomKey
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
readKeyFileBase16 = readKeyFile \a ->
   case BA.span (not . rn) a of
      (pre, pos)
         | BA.all rn pos -> BA.convertFromBase BA.Base16 pre
         | otherwise -> Left "invalid format"
  where
   _r :: Word8 = fromIntegral (Char.ord '\r')
   _n :: Word8 = fromIntegral (Char.ord '\n')
   rn :: Word8 -> Bool = \w -> w == _r || w == _n

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
         Right kraw -> case keyFromBytes kraw of
            Right key -> pure key
            Left err -> fail $ "readKeyFile: " <> err

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
   kout <- Ex.evaluate $ g $ keyToBytes key
   IO.withFile path IO.WriteMode \h ->
      BA.withByteArray kout \p ->
         IO.hPutBuf h p $ BA.length kout

-- | Base-16 encoded.
instance (Encryption e) => Ae.FromJSON (Key e) where
   parseJSON = Ae.withText "Key" \t ->
      -- Note that un-scrubbable bytes will continue to exist in @t@.
      case BA.convertFromBase BA.Base16 (T.encodeUtf8 t) of
         Right (kraw :: BA.ScrubbedBytes) ->
            case keyFromBytes kraw of
               Right key -> pure key
               Left err -> fail err
         _ -> fail "Invalid key"
