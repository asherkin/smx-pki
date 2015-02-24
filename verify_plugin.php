<?php

require('vendor/autoload.php');

include('File/X509.php');
include('Crypt/RSA.php');

$plugin = file_get_contents('./output/plugin-signed.smx');

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

if ($sections[0]['dataoffs'] >= $header['dataoffs']) {
  throw new Exception('[INCOMPLETE] Signature section needs to be first and uncompressed.');
}

$signature_section = substr($plugin, $sections[0]['dataoffs'], $sections[0]['size']);

$certs_info = unpack('Cversion/Ccount/Llength', $signature_section);

if ($certs_info['version'] !== 1) {
  throw new Exception('Bad .signature section version.');
}

if ($certs_info['count'] !== 1) {
  throw new Exception('[INCOMPLETE] Only a single signing certificate is supported.');
}

$cert = substr($signature_section, 6, $certs_info['length']);

$signer = new File_X509();
$signer->loadX509($cert);

$signer->loadCA(file_get_contents('./output/user_ca.crt'));
$signer->loadCA(file_get_contents('./output/root_ca.crt'));

echo 'Signing Certifiace Issuer: ' . $signer->getIssuerDN(FILE_X509_DN_STRING) . PHP_EOL;
echo 'Signing Certifiace Subject: ' . $signer->getSubjectDN(FILE_X509_DN_STRING) . PHP_EOL;
echo 'Signing Certificate Valid: ' . ($signer->validateSignature() ? 'TRUE' : 'FALSE') . PHP_EOL;

$signature_length = $signer->getPublicKey()->getSize() / 8;

$signature_info = unpack('Calgorithm', substr($signature_section, -($signature_length + 1), 1));

if ($signature_info['algorithm'] !== 1) {
  throw new Exception('Bad signature algorithm.');
}

$signature = substr($signature_section, -$signature_length);

if (strlen($signature) != $signature_length) {
  throw new Exception('Bad signature section.');
}

$plaintext = substr_replace($plugin, str_repeat(chr(0), $signature_length), ($sections[0]['dataoffs'] + $sections[0]['size']) - $signature_length, $signature_length);

$pubKey = $signer->getPublicKey();
$pubKey->setHash('sha256');
$pubKey->setMGFHash('sha256');
$pubKey->setSignatureMode(CRYPT_RSA_SIGNATURE_PSS);
echo 'Signature Valid: ' . ($pubKey->verify($plaintext, $signature) ? 'TRUE' : 'FALSE') . PHP_EOL;

