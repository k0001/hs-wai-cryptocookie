# Version 0.1.1

* The `CryptoCookie` won't be decrypted and decoded until `get` is
  used. This makes requests that don't need to interact with the
  `CryptoCookie` more efficient.


# Version 0.1

* Changed the type of `middleware` so that the previous *lookup*
  function is not used anymore. Instead, a `CryptoCookie` is
  provided directly to an `Application`-construction function.


# Version 0.0.1

* Initial version.
