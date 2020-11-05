<?php

    /**
     * Para generar una nueva firma debes mandar los datos solicitados
     * 
     * En el contructor de la case OpensslGenerate debes indicar las 3 carpetas donde se guardaran los
     * archivos key y cer.
     * Example: new OpensslGenerate(certificate_url, private_key_url, public_key_url) : void
     * 
     * En el metodo generate_sign debes enviar los datos que estaran incluidos en el certificado y junto auna contraseña
     * esto retornara un array en el cual indica la ruta y nombre de archivo.
     * Example: $generate_sign->generate_sign($data, $pass) : array
     * 
     */
    include "../openssl.class.php";
    $generate_sign = new \Avispaa\OpensslGenerate("../crt/", "../prkey/", "../pbkey/");
    print_r($generate_sign->generate_identify([
        "countryName" => "MX",
        "stateOrProvinceName" => "Somerset",
        "localityName" => "Glastonbury",
        "organizationName" => "The Brain Room Limited",
        "organizationalUnitName" => "PHP Documentation Team",
        "commonName" => "Wez Furlong",
        "emailAddress" => "wez@example.com"
    ], "josuechido"));