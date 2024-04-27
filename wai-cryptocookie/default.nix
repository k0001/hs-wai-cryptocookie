{ mkDerivation, aeson, base, binary, bytestring, cookie, crypton
, directory, filepath, http-types, lib, memory, stm, text, time
, vault, wai, wai-extra
}:
mkDerivation {
  pname = "wai-cryptocookie";
  version = "0.0.1";
  src = ./.;
  libraryHaskellDepends = [
    aeson base binary bytestring cookie crypton http-types memory stm
    text time vault wai
  ];
  testHaskellDepends = [
    aeson base binary directory filepath stm wai wai-extra
  ];
  homepage = "https://gitlab.com/k0001/hs-wai-cryptocookie";
  description = "Encrypted cookies for WAI";
  license = lib.licenses.asl20;
}
