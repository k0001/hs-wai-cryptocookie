{ mkDerivation, aeson, base, binary, bytestring, cookie, crypton
, http-types, lib, memory, stm, time, vault, wai
}:
mkDerivation {
  pname = "wai-session-cookie";
  version = "0.0.1";
  src = ./.;
  libraryHaskellDepends = [
    aeson base binary bytestring cookie crypton http-types memory stm
    time vault wai
  ];
  homepage = "https://gitlab.com/k0001/hs-wai-session-cookie";
  description = "Encrypted session cookies for WAI";
  license = lib.licenses.asl20;
}
