#!/usr/bin/php
<?php
$key="1q2w3e4r5t6y7u89";
$iv="azsxdcfvgbhnjmkl";


function aes128_cbc_encrypt($key, $data, $iv) {
  if(16 !== strlen($key)) $key = hash('MD5', $key, true);
  if(16 !== strlen($iv)) $iv = hash('MD5', $iv, true);
  $padding = 16 - (strlen($data) % 16);
  $data .= str_repeat(chr($padding), $padding);
  return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
}
function aes256_cbc_encrypt($key, $data, $iv) {
  if(32 !== strlen($key)) $key = hash('SHA256', $key, true);
  if(16 !== strlen($iv)) $iv = hash('MD5', $iv, true);
  $padding = 16 - (strlen($data) % 16);
  $data .= str_repeat(chr($padding), $padding);
  return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
}
function aes128_cbc_decrypt($key, $data, $iv) {
  if(16 !== strlen($key)) $key = hash('MD5', $key, true);
  if(16 !== strlen($iv)) $iv = hash('MD5', $iv, true);
  $data = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
  $padding = ord($data[strlen($data) - 1]);
  return substr($data, 0, -$padding);
}
function aes256_cbc_decrypt($key, $data, $iv) {
  if(32 !== strlen($key)) $key = hash('SHA256', $key, true);
  if(16 !== strlen($iv)) $iv = hash('MD5', $iv, true);
  $data = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
  $padding = ord($data[strlen($data) - 1]);
  return substr($data, 0, -$padding);
}

$data=aes128_cbc_encrypt($key,$argv[1],$iv);

$encr = base64_encode($data);
echo $encr."\n";

$decr=base64_decode($encr);
$data=aes128_cbc_decrypt($key,$decr,$iv);

echo $data."\n";
?>
