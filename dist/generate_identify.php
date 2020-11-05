<?php
    include "../openssl.class.php";
    $generate_sign = new \Avispaa\OpensslGenerate("../crt/", "../prkey/", "../pbkey/");
    // print_r($generate_sign->create_sign(file_get_contents('../crt/sign-70075177-201104095046.cer'), file_get_contents('../prkey/sign-70075177-201104095046.pem'), file_get_contents('../pbkey/sign-70075177-201104095046.pem'), "josuechido", ["josue-el-chido", "hernandez-pro"]));
    print_r($generate_sign->create_sign(
        wordwrap(file_get_contents('../crt/sign-88295642-201105014834.cer')), 
        wordwrap(file_get_contents('../prkey/sign-88295642-201105014834.key')), 
        wordwrap(file_get_contents('../pbkey/sign-88295642-201105014834.pem')), 
        "josuechido", 
        ["josue-el-chido", "hernandez-pro"]
    ));