{-# LANGUAGE StrictData #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Wai.CryptoCookie.Encryption.AEAD_AES_256_GCM_SIV () where

import Crypto.Cipher.AES qualified as CAES
import Crypto.Cipher.AESGCMSIV qualified as CAGS
import Crypto.Cipher.Types qualified as CAES
import Crypto.Error qualified as C
import Crypto.Random qualified as C
import Data.ByteArray qualified as BA
import Data.ByteArray.Parse qualified as BAP
import Data.ByteArray.Sized qualified as BAS
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as BL

import Wai.CryptoCookie.Encryption

-- | @AEAD_AES_256_GCM_SIV@ is a nonce-misuse resistant AEAD encryption scheme
-- defined in <https://tools.ietf.org/html/rfc8452 RFC 8452>.
instance Encryption "AEAD_AES_256_GCM_SIV" where
   newtype Key "AEAD_AES_256_GCM_SIV"
      = Key (BAS.SizedByteArray 32 BA.ScrubbedBytes)
      deriving newtype (Eq)
   type KeyLength "AEAD_AES_256_GCM_SIV" = 32
   data Encrypt "AEAD_AES_256_GCM_SIV"
      = Encrypt CAES.AES256 C.ChaChaDRG CAGS.Nonce
   newtype Decrypt "AEAD_AES_256_GCM_SIV"
      = Decrypt CAES.AES256
   genKey = fmap (Key . BAS.unsafeSizedByteArray) (C.getRandomBytes 32)
   keyFromBytes =
      maybe (Left "Bad length") (Right . Key) . BAS.fromByteArrayAccess
   keyToBytes (Key key) = BAS.convert key
   initial (Key key0) = do
      drg0 <- C.drgNew
      let (nonce, drg1) = C.withDRG drg0 CAGS.generateNonce
          aes = C.throwCryptoError $ CAES.cipherInit $ BAS.unSizedByteArray key0
      pure (Encrypt aes drg1 nonce, Decrypt aes)
   advance (Encrypt aes drg0 _) =
      let (nonce, drg1) = C.withDRG drg0 CAGS.generateNonce
      in  Encrypt aes drg1 nonce
   encrypt (Encrypt aes _ nonce) plain =
      let (tag, cry) = CAGS.encrypt aes nonce B.empty $ B.toStrict plain
      in  BL.fromChunks [BA.convert nonce, BA.convert tag, cry]
   decrypt = \(Decrypt aes) raw -> do
      (nonce, tag, cry) <- fromResult $ BAP.parse p (B.toStrict raw)
      case CAGS.decrypt aes nonce B.empty cry tag of
         Just x -> pure $ BL.fromStrict x
         Nothing -> Left "Can't decrypt"
     where
      p :: BAP.Parser B.ByteString (CAGS.Nonce, CAES.AuthTag, B.ByteString)
      p = do
         C.CryptoPassed nonce <- CAGS.nonce <$> BAP.take 12
         tag <- CAES.AuthTag . BA.convert <$> BAP.take 16
         cry <- BAP.takeAll
         pure (nonce, tag, cry)

fromResult :: BAP.Result B.ByteString a -> Either String a
fromResult = \case
   BAP.ParseOK rest a
      | B.null rest -> Right a
      | otherwise -> Left "Leftovers"
   BAP.ParseMore f -> fromResult (f Nothing)
   BAP.ParseFail e -> Left e
