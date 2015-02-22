<?php

require('vendor/autoload.php');

include('File/X509.php');
include('Crypt/RSA.php');

$username = 'asherkin';

$CAPrivKey = new Crypt_RSA();
$CAPrivKey->loadKey(file_get_contents('./output/user_ca.key'));

$issuer = new File_X509();
$issuer->loadX509(file_get_contents('./output/user_ca.crt'));
$issuer->setPrivateKey($CAPrivKey);

$privKey = new Crypt_RSA();
$keys = $privKey->createKey(2048);
$privKey->loadKey($keys['privatekey']);

$pubKey = new Crypt_RSA();
$pubKey->loadKey($keys['publickey']);
$pubKey->setPublicKey();

$subject = new File_X509();
$subject->setDNProp('id-at-commonName', $username);
$subject->setDNProp('id-at-organizationalUnitName', 'AlliedModders Users');
$subject->setDNProp('id-at-organizationName', 'AlliedModders');
$subject->setPublicKey($pubKey);

$x509 = new File_X509();
$x509->setEndDate('+2 years');
//$x509->setSerialNumber('0xDEADBEEF', 16);
$result = $x509->sign($issuer, $subject);

$x509->loadX509($result);
$x509->setExtension('id-ce-keyUsage', array('digitalSignature'), true);
$x509->setExtension('id-ce-extKeyUsage', array('id-kp-codeSigning'), true);
$result = $x509->sign($issuer, $x509);

if (!is_dir('./output/users/')) {
  mkdir('./output/users/');
}

file_put_contents('./output/users/'.$username.'.key', $keys['privatekey']);
file_put_contents('./output/users/'.$username.'.crt', $x509->saveX509($result));

