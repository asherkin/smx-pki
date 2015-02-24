<?php

require('vendor/autoload.php');

include('File/X509.php');
include('Crypt/RSA.php');

$CAPrivKey = new Crypt_RSA();
$CAPrivKey->loadKey(file_get_contents('./output/root_ca.key'));

$issuer = new File_X509();
$issuer->loadX509(file_get_contents('./output/root_ca.crt'));
$issuer->setPrivateKey($CAPrivKey);

$privKey = new Crypt_RSA();
$keys = $privKey->createKey(2048);
$privKey->loadKey($keys['privatekey']);

$pubKey = new Crypt_RSA();
$pubKey->loadKey($keys['publickey']);
$pubKey->setPublicKey();

$subject = new File_X509();
$subject->setDNProp('id-at-commonName', 'AlliedModders User Intermediate CA');
$subject->setDNProp('id-at-organizationName', 'AlliedModders');
$subject->setPublicKey($pubKey);

$x509 = new File_X509();
$x509->makeCA();
$x509->setEndDate('+10 years');
$result = $x509->sign($issuer, $subject, 'sha256WithRSAEncryption');

file_put_contents('./output/user_ca.key', $keys['privatekey']);
file_put_contents('./output/user_ca.crt', $x509->saveX509($result));

