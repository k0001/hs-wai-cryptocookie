{ mkDerivation, aeson, base, binary, bytestring, cookie, crypton
, http-types, lib, memory, stm, text, time, vault, wai
}:
mkDerivation {
  pname = "wai-cryptocookie";
  version = "0.0.1";
  src = ./.;
  libraryHaskellDepends = [
    aeson base binary bytestring cookie crypton http-types memory stm
    text time vault wai
  ];
  homepage = "https://gitlab.com/k0001/hs-wai-cryptocookie";
  description = "Encrypted cookies for WAI";
  license = lib.licenses.asl20;
}
