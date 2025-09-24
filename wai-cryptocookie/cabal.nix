{ mkDerivation, aeson, base, binary, bytestring, case-insensitive
, cookie, crypton, directory, filepath, http-types, lib, memory
, text, time, wai, wai-csrf, wai-extra
}:
mkDerivation {
  pname = "wai-cryptocookie";
  version = "0.3";
  src = ./.;
  libraryHaskellDepends = [
    aeson base binary bytestring case-insensitive cookie crypton
    http-types memory text time wai wai-csrf
  ];
  testHaskellDepends = [
    base bytestring cookie directory filepath http-types wai wai-extra
  ];
  homepage = "https://github.com/k0001/hs-wai-cryptocookie";
  description = "Encrypted cookies for WAI";
  license = lib.licenses.asl20;
}
