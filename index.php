<?php
// datos que se quieren firmar
$datos = 'mis datos';

// crear unas claves pública y privada nuevas
$new_key_pair = openssl_pkey_new(array(
    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
));

openssl_pkey_export($new_key_pair, $private_key_pem);

$details = openssl_pkey_get_details($new_key_pair);
$public_key_pem = $details['key'];

// crear la firma
openssl_sign($datos, $firma, $private_key_pem, OPENSSL_ALGO_SHA256);

// guardar para después
file_put_contents('private_key.pem', $private_key_pem);
file_put_contents('public_key.pem', $public_key_pem);
file_put_contents('signature.dat', $firma);

// comprobar la firma
$r = openssl_verify($datos, $firma, $public_key_pem, "sha256WithRSAEncryption");
var_dump($r);
?>