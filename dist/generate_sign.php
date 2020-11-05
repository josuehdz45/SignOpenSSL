<?php
    /**
     * Para generar una frima debes tener los datos a firmar, certificado y llave privada
     * 
     * Por parametros posicionales debes enviar en un strign con los certificados y llaves correspondientes para el caso
     * de la llave publica esa estara almacenada en el registro del usurio, por lo cual se guardara como ruta y tu debes obtenerlo y
     * sacar el string dentor, esta llave esta en formato .pem
     * 
     * @param 1 - Debo contener el certificado en formato string, no enviar el archivo ya que no lo reconocera
     * @param 2 - Debe contener la llave privada que esta en formato .key, tambien debes obtener el contenido y enviarlo en string
     * @param 3 - Debe contener la llave publica que esta en formato .pem
     * @param 4 - La contraseña, si no hay contraseña mamndarlo como null
     * @param 5 - Datos a firmar
     * 
     * Esto te regresara un firma en formato binario, por lo cual es recomendable ponerlo en formato texto o bien encriptarlo
    */
    include "../openssl.class.php";
    $generate_sign = new \Avispaa\OpensslGenerate("../crt/", "../prkey/", "../pbkey/");
    print_r($generate_sign->create_sign(
        file_get_contents('../crt/sign-5489631-201105052201.cer'), 
        file_get_contents('../prkey/sign-5489631-201105052201.key'), 
        file_get_contents('../pbkey/sign-5489631-201105052201.pem'), 
        "password", 
        ["name", "lastname"]
    ));