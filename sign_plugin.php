<?php

require('vendor/autoload.php');

include('File/X509.php');
include('Crypt/RSA.php');

$plugin = file_get_contents('./plugin.smx');

$header = unpack('Lmagic/Sversion/Ccompression/Ldisksize/Limagesize/Csections/Lstringtab/Ldataoffs', substr($plugin, 0, 24));

if ($header['magic'] !== 0x53504646) {
  throw new Exception('Bad magic number.');
}

if ($header['compression'] !== 1) {
  throw new Exception('SMX compression is mandatory.');
}

//print_r($header);

$sections = array();
for ($i = 0; $i < $header['sections']; $i++) {
  $sections[] = unpack('Lnameoffs/Ldataoffs/Lsize', substr($plugin, 24 + ($i * 12), 12)); 
}

//print_r($sections);

$names = explode(chr(0), substr($plugin, $header['stringtab'], $header['dataoffs'] - $header['stringtab']), $header['sections'] + 1);
array_pop($names);

//print_r($names);

$compressed = substr($plugin, $header['dataoffs'], $header['disksize'] - $header['dataoffs']);

/*
$data = gzuncompress(substr($plugin, $header['dataoffs'], $header['disksize'] - $header['dataoffs']));

if ($data === false) {
  throw new Exception('Failed to decompress data.');
}

if (strlen($data) !== ($header['imagesize'] - $header['dataoffs'])) {
  throw new Exception('Decompressed data did not match expected size.');
}

//print_r(array('hash' => md5($data), 'size' => strlen($data)));
*/

$signcert = new File_X509();
$signer = $signcert->loadX509(file_get_contents('./output/users/asherkin.crt'));

$x509 = new File_X509();
$signer = $x509->saveX509($signer, FILE_X509_FORMAT_DER);
$intermediate = $x509->saveX509($x509->loadX509(file_get_contents('./output/user_ca.crt')), FILE_X509_FORMAT_DER);

$signature_length = $signcert->getPublicKey()->getSize() / 8;

// version, certificate count, der-encoded certificates prefixed with length, signature version (1 = SHA256 RSASSA-PSS), signature (placeholder)
$signature_section = pack('CC', 0, 1) . (pack('L', strlen($signer)) . $signer) . /*(pack('L', strlen($intermediate)) . $intermediate) .*/ pack('C', 1) . str_repeat(chr(0), $signature_length);
$signature_size = strlen($signature_section);

//print_r(array('hash' => md5($signature_section), 'size' => $signature_size));

array_unshift($names, '.signature');

for ($i = 0; $i < $header['sections']; $i++) {
  $sections[$i]['nameoffs'] += strlen('.signature') + 1;
  $sections[$i]['dataoffs'] += 12 + (strlen('.signature') + 1) + $signature_size;
}

$header['dataoffs'] += 12 + (strlen('.signature') + 1);
array_unshift($sections, array('nameoffs' => 0, 'dataoffs' => $header['dataoffs'], 'size' => $signature_size));
$header['dataoffs'] += $signature_size;

$header['disksize'] += 12 + (strlen('.signature') + 1) + $signature_size;
$header['imagesize'] += 12 + (strlen('.signature') + 1) + $signature_size;
$header['sections'] += 1;
$header['stringtab'] += 12;

//print_r($header);
//print_r($sections);
//print_r($names);

$data = pack('LSCLLCLL', $header['magic'], $header['version'], $header['compression'], $header['disksize'], $header['imagesize'], $header['sections'], $header['stringtab'], $header['dataoffs']);

for ($i = 0; $i < $header['sections']; $i++) {
  $data .= pack('LLL', $sections[$i]['nameoffs'], $sections[$i]['dataoffs'], $sections[$i]['size']);
}

$data .= implode(chr(0), $names) . chr(0);

$data .= $signature_section;

$data .= $compressed;

//print_r(array('hash' => md5($data), 'size' => strlen($data)));

$privKey = new Crypt_RSA();
$privKey->loadKey(file_get_contents('./output/users/asherkin.key'));

$privKey->setHash('sha256');
$privKey->setMGFHash('sha256');
$privKey->setSignatureMode(CRYPT_RSA_SIGNATURE_PSS);
$signature = $privKey->sign($data);

if (strlen($signature) != $signature_length) {
  throw new Exception('Signature length mismatch.');
}

$data = substr_replace($data, $signature, $header['dataoffs'] - $signature_length, $signature_length);

//print_r(array('hash' => md5($data), 'size' => strlen($data)));

file_put_contents('./output/plugin-signed.smx', $data);
