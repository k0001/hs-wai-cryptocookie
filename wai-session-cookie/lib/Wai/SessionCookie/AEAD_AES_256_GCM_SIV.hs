{-# OPTIONS_GHC -Wno-orphans #-}
{-# LANGUAGE StrictData #-}

module Wai.SessionCookie.AEAD_AES_256_GCM_SIV () where

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

import Wai.SessionCookie.Internal

instance Encryption "AEAD_AES_256_GCM_SIV" where
   newtype Key "AEAD_AES_256_GCM_SIV"
      = Key (BAS.SizedByteArray 32 BA.ScrubbedBytes)
   type KeyLength "AEAD_AES_256_GCM_SIV" = 32
   data Encrypt "AEAD_AES_256_GCM_SIV"
      = Encrypt CAES.AES256 C.ChaChaDRG CAGS.Nonce
   newtype Decrypt "AEAD_AES_256_GCM_SIV"
      = Decrypt CAES.AES256
   genKey = fmap (Key . BAS.unsafeSizedByteArray) (C.getRandomBytes 32)
   loadKey = fmap Key . BAS.fromByteArrayAccess
   dumpKey (Key key) = BAS.convert key
   initial (Key key0) = do
      drg0 <- C.drgNew
      let (nonce, drg1) = C.withDRG drg0 CAGS.generateNonce
          key1 = BA.convert key0 :: BA.ScrubbedBytes
          aes = C.throwCryptoError $ CAES.cipherInit key1
      pure (Encrypt aes drg1 nonce, Decrypt aes)
   advance (Encrypt aes drg0 _) =
      let (nonce, drg1) = C.withDRG drg0 CAGS.generateNonce
      in  Encrypt aes drg1 nonce
   encrypt (Encrypt aes _ nonce) plain =
      let (tag, cry) = CAGS.encrypt aes nonce B.empty $ B.toStrict plain
      in  BL.fromChunks [BA.convert nonce, BA.convert tag, cry]
   decrypt (Decrypt aes) raw = do
      BAP.ParseOK _ (nonce, tag, cry) <-
         pure $ flip BAP.parse (B.toStrict raw) do
            C.CryptoPassed nonce <- CAGS.nonce <$> BAP.take 12
            tag <- CAES.AuthTag . BA.convert <$> BAP.take 16
            cry <- BAP.takeAll
            pure (nonce, tag, cry)
      BL.fromStrict <$> CAGS.decrypt aes nonce B.empty cry tag

