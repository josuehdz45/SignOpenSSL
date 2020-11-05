<?php
    namespace Avispaa;
    
    /** 
     * @author Josué Hernández <josue.hernandez@vlim.com.mx>
     * @package ini
     */
    class OpensslGenerate{

        private $crt_route;
        private $key_route;
        private $pbkey_route;

        /**
         * @param string $get_crt_route - debes colocar la ruta donde deseas guardar el certificado ejemplo: crt/
         * @param string $get_key_route - Debes colocar la ruta donde deseas guarda la llave privada ejemplo: prkey/
         * @param string $get_pbkey_route - Debes colocar la ruta donde se guardara la llave publica ejemplo: pbkey/
         */
        function __construct(string $get_crt_route, string $get_key_route, string $get_pbkey_route){
            $this->crt_route = filter_var($get_crt_route, FILTER_SANITIZE_URL);
            $this->key_route = filter_var($get_key_route, FILTER_SANITIZE_URL);
            $this->pbkey_route = filter_var($get_pbkey_route, FILTER_SANITIZE_URL);
        }

        /**
         * Genera un cer y un key el cual se almacena en las carpetas especificadas
         * @param array $dn - Aquí van los datos que deseas guardar dentro del certificado example: $dn = array(
                "countryName" => "UK",
                "stateOrProvinceName" => "Somerset",
                "localityName" => "Glastonbury",
                "organizationName" => "The Brain Room Limited",
                "organizationalUnitName" => "PHP Documentation Team",
                "commonName" => "Wez Furlong",
                "emailAddress" => "wez@example.com"
            );
         * @param string $pass - Es un palabra que funcionara como identificador para la llave privada, publica y el certificado
         */
        public function generate_identify(array $dn = [], string $pass = "") : array {
            try{
                // Generar una nueva pareja de clave privada (y pública)
                $files_name = "sign-".rand(0, 99999999).date("-ymdhis");
                if(!file_exists("{$this->crt_route}{$files_name}.cer") || !file_exists("{$this->key_route}$files_name.key")){
                    
                    // Genetate a new key
                    $privkey = openssl_pkey_new(array(
                        "private_key_bits" => 2048,
                        "private_key_type" => OPENSSL_KEYTYPE_RSA,
                    ));
                    
                    // Export the private key to string and save the password
                    openssl_pkey_export($privkey, $pkeyout); // and var_dump($pkeyout)
                    $get_pub_key = openssl_pkey_get_details($privkey);
                    openssl_private_decrypt($get_pub_key,$newsource,$pkeyout);

                    // We cretare a new certificate with the private key
                    $csr = openssl_csr_new($dn, $privkey);
                    // Create a new sign for the certificate with a 3 year of live
                    $sscert = openssl_csr_sign($csr, null, $privkey, 365*3);
                    // Exporto to strign the certificate
                    openssl_csr_export($csr, $csrout); // and var_dump($csrout)
                    // Create a new x509 
                    openssl_x509_export($sscert, $certout); // and var_dump($certout)
                    
                    // We create a new files with the cer, pub key and priv key
                    file_put_contents("{$this->crt_route}{$files_name}.cer", $certout);
                    file_put_contents("{$this->key_route}{$files_name}.key", $newsource);
                    file_put_contents("{$this->pbkey_route}{$files_name}.pem", $get_pub_key['key']);
                    // Return the data for the user peticion
                    return (array) [
                        "prkey" => $files_name.".key",
                        "pbkey" => $files_name.".pem",
                        "cer" => $files_name.".cer"
                    ];
                }else{
                    return (array) [
                        "error" => "I'm sorry, this file was created in the past",
                    ];
                }
            }catch(\Exception $e){
                print("You have error in generate_sign: {$e->getMessage()}");
            }
        }
        
        /**
         * 
         */
        public function create_sign(string $cer_data, string $private_key, string $pub_key, string $pass, array $data) : string{
            try{
                $data = implode(",", $data);
                // Validamos que el certificado corresponda a la llave privada generada
                $keyPassphrase = $pass;
                $keyCheckData = [$private_key, $keyPassphrase];
                $verify_priv_key = openssl_x509_check_private_key($cer_data, $keyCheckData); 
                if($verify_priv_key == 1){
                    // crear la firma
                    $response = '';
                    openssl_sign($data, $firma, $private_key, OPENSSL_ALGO_SHA256);
                    if($this->verify_sign($pub_key, $data, $firma)){
                        $response = $firma;
                    }
                    else{
                        $response = "Ocurrio un error no se puede validar";
                    }
                    return (string) $private_key;
                }else{
                    return "ya valio xd";
                }
            }catch(\Exception $e){
                print("You have an error in create_sign method: {$e->getMessage()}");
            }
        }

        private function verify_sign(string $pub_key, string $datos, $sign) : bool{
            return (bool) openssl_verify($datos, $sign, $pub_key, "sha256WithRSAEncryption");
        }
    }
?>