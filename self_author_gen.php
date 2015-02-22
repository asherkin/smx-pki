<?php

require('vendor/autoload.php');

include('File/X509.php');
include('Crypt/RSA.php');

$username = 'asherkin';

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

$issuer = new File_X509();
$issuer->setPrivateKey($privKey);
$issuer->setDN($subject->getDN());

$x509 = new File_X509();
$x509->setEndDate('+2 years');
$result = $x509->sign($issuer, $subject);

if (!is_dir('./output/users/')) {
  mkdir('./output/users/');
}

file_put_contents('./output/users/'.$username.'-self.key', $keys['privatekey']);
file_put_contents('./output/users/'.$username.'-self.crt', $x509->saveX509($result));

