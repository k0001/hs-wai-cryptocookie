{ mkDerivation, aeson, base, binary, bytestring, cookie, crypton
, directory, filepath, http-types, lib, memory, stm, text, time
, wai, wai-extra
}:
mkDerivation {
  pname = "wai-cryptocookie";
  version = "0.2";
  src = ./.;
  libraryHaskellDepends = [
    aeson base binary bytestring cookie crypton http-types memory stm
    text time wai
  ];
  testHaskellDepends = [
    aeson base binary directory filepath http-types stm wai wai-extra
  ];
  homepage = "https://github.com/k0001/hs-wai-cryptocookie";
  description = "Encrypted cookies for WAI";
  license = lib.licenses.asl20;
}
