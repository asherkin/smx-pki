<?php

require('vendor/autoload.php');

include('File/X509.php');
include('Crypt/RSA.php');

$privKey = new Crypt_RSA();
$keys = $privKey->createKey(2048);
$privKey->loadKey($keys['privatekey']);

$pubKey = new Crypt_RSA();
$pubKey->loadKey($keys['publickey']);
$pubKey->setPublicKey();

$subject = new File_X509();
$subject->setDNProp('id-at-commonName', 'AlliedModders Root CA');
$subject->setDNProp('id-at-organizationName', 'AlliedModders');
$subject->setPublicKey($pubKey);

$issuer = new File_X509();
$issuer->setPrivateKey($privKey);
$issuer->setDN($subject->getDN());

$x509 = new File_X509();
$x509->makeCA();
$x509->setEndDate('+20 years');
$result = $x509->sign($issuer, $subject, 'sha256WithRSAEncryption');

if (!is_dir('./output/')) {
  mkdir('./output/');
}

file_put_contents('./output/root_ca.key', $keys['privatekey']);
file_put_contents('./output/root_ca.crt', $x509->saveX509($result));

