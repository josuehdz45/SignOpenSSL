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
                    openssl_pkey_export($privkey, $pkeyout); // Export the private key to string and save the password
                    $get_pub_key = openssl_pkey_get_details($privkey);
                    $csr = openssl_csr_new($dn, $privkey); // We cretare a new certificate with the private key
                    $sscert = openssl_csr_sign($csr, null, $privkey, 365*3); // Create a new sign for the certificate with a 3 year of live
                    openssl_csr_export($csr, $csrout); // Exporto to strign the certificate
                    openssl_x509_export($sscert, $certout); // Create a new x509 
                    file_put_contents("{$this->crt_route}{$files_name}.cer", $certout); // We create a new files with the cer, pub key and priv key
                    file_put_contents("{$this->key_route}{$files_name}.key", $pkeyout);
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
         * Se genera una nueva firma, retorna una la firma validada
         * @param string $cer_data - Debe tener el certificado generado anteriormente en formato string, es decir debes enviar la cadena no el archivo
         * @param string $private_key - Debe tener la llave privada en formato string
         * @param string $pub_key - Debe tener una llave publica en formato string
         * @return string Esto te regresara la firma verificada y si se tiene un error regresara el codigo: 3001 - No se puede validar esta firma, 3002 - La llave privada y el certificado no coinciden
         */
        public function create_sign(string $cer_data, string $private_key, string $pub_key, string $pass, array $data) : string{
            try{
                $dataForSign = implode(",", $data);
                // Validamos que el certificado corresponda a la llave privada generada
                // Creamos un array que contiene la llave privada y su contraseña
                $keyCheckData = [$private_key, null];
                $verify_priv_key = openssl_x509_check_private_key($cer_data, $keyCheckData);
                if($verify_priv_key == 1){
                    openssl_sign($dataForSign, $firma, $private_key, OPENSSL_ALGO_SHA256);    
                    return (string) ($this->verify_sign($pub_key, $dataForSign, $firma)) ? $firma : "3001";
                }else{
                    return (string) "La llave privada y el certificado no coinciden";
                }   
            }catch(\Exception $e){
                print("You have an error in create_sign method: {$e->getMessage()}");
            }
        }

        /**
         * Verifica una firma con la llave publica y la encrptación
         * @param string $pub_key
         * @param string $datos
         * @param string $sign
         * @return bool
         */
        private function verify_sign(string $pub_key, string $datos, $sign) : bool{
            return (bool) openssl_verify($datos, $sign, $pub_key, "sha256WithRSAEncryption");
        }
    }
?>