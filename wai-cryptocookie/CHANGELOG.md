# Version 0.2

* BREAKING CHANGE: The type of `set` changed so that `set cc Nothing` is
  now `delete cc`, and `set cc (Just a)` is now `set cc a`.

* Added a function `keep` to keep the cookie as is on the client side,
  without sending any `Set-Cookie` header on the reply.

* The `CryptoCookie` won't be decrypted and decoded until `get` is
  used. This makes requests that don't need to interact with the
  `CryptoCookie` more efficient.

* Documentation improvements.


# Version 0.1

* Changed the type of `middleware` so that the previous *lookup*
  function is not used anymore. Instead, a `CryptoCookie` is
  provided directly to an `Application`-construction function.


# Version 0.0.1

* Initial version.
