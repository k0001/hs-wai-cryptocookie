{-# LANGUAGE StrictData #-}
{-# LANGUAGE NoFieldSelectors #-}

-- | You will need to import this module if you are planning to define
-- or use a 'Encoding' other than the defaults provided by this library.
module Wai.CryptoCookie.Encoding
   ( Encoding (..)
   , aeson
   , binary
   ) where

import Data.Aeson qualified as Ae
import Data.Binary qualified as Bin
import Data.ByteString.Lazy qualified as BL
import Data.Kind (Type)

-- | How to encode and decode a value of type @a@ into a 'BL.ByteString'.
data Encoding (a :: Type) = Encoding
   { encode :: a -> BL.ByteString
   , decode :: BL.ByteString -> Maybe a
   }

-- | Encode and decode use 'Bin.Binary' from the @binary@ library.
binary :: (Bin.Binary a) => Encoding a
binary =
   Encoding
      { encode = Bin.encode
      , decode = \bl -> case Bin.decodeOrFail bl of
         Right (_, _, a) -> Just a
         Left _ -> Nothing
      }

-- | Encode and decode use 'Ae.ToJSON' and 'Ae.FromJSON' from
-- the @aeson@ library.
aeson :: (Ae.FromJSON a, Ae.ToJSON a) => Encoding a
aeson = Encoding{encode = Ae.encode, decode = Ae.decode}
