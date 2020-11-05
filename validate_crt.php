<?php 

    // Validamos que el certificado corresponda a la llave privada generada
    $certFile = file_get_contents('cert.crt');
    $keyFile = file_get_contents('cert.key');
    $keyPassphrase = "thisisexample";
    $keyCheckData = [$keyFile, $keyPassphrase];
    // $keyCheckData = array(0 => $keyFile, 1=> $keyPassphrase);
    $result = openssl_x509_check_private_key($certFile, $keyCheckData);
    print($result);