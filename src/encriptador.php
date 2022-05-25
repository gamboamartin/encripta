<?php
/**
 * @author Martin Gamboa Vazquez
 * @version 1.1.0
 * Encripta y desencripta valores entregados
 */
namespace gamboamartin\encripta;


use config\generales;
use gamboamartin\errores\errores;
use gamboamartin\validacion\validacion;
use stdClass;
use Throwable;

class encriptador{
    private string $clave ;
    private bool $aplica_encriptacion = false;
    private string $metodo_encriptacion;
    private string $iv;
    private errores $error;

    public function __construct(string $clave = '', string $iv = '', string $metodo_encriptacion = ''){
        $this->error = new errores();

        $init = $this->inicializa_valores(clave: $clave,metodo_encriptacion: $metodo_encriptacion,iv: $iv);
        if(errores::$error){
            $error = $this->error->error(mensaje: 'Error al inicializar datos', data: $init);
            print_r($error);
            die('Error');
        }
        if($init->clave !==''){
            $this->aplica_encriptacion = true;
        }

        $this->clave = $init->clave;
        $this->metodo_encriptacion = $init->metodo_encriptacion;
        $this->iv = $init->iv;

    }

    /**
     * Desencripta un valor entregado
     * @version 1.0.0
     * @param string $valor Valor a desencriptar
     * @return string|array
     */
    public function desencripta(string $valor): string|array
    {
        $desencriptado = $valor;
        if($this->aplica_encriptacion) {
            try {
                $verifica = $this->verifica_datos();
                if(errores::$error){
                    return $this->error->error(mensaje: 'Error al verificar datos', data: $verifica);
                }
                $desencriptado = openssl_decrypt($valor, $this->metodo_encriptacion, $this->clave, false,
                    $this->iv);
            }
            catch (Throwable $e){
                return $this->error->error(mensaje: 'Error al desencriptar',data:  $e);
            }
        }
        return $desencriptado;
    }

    /**
     * Encripta un valor conforme al metodo cargado en generales
     * @version 1.0.0
     * @param string $valor Valor a encriptar
     * @return string|array
     */
    public function encripta(string $valor): string|array
    {
        $encriptado = $valor;
        if($this->aplica_encriptacion){

            $verifica = $this->verifica_datos();
            if(errores::$error){
                return $this->error->error(mensaje: 'Error al verificar datos', data: $verifica);
            }

            $encriptado = openssl_encrypt ($valor, $this->metodo_encriptacion, $this->clave, false,$this->iv);
        }
        return $encriptado;

    }

    /**
     * Inicializa los valores para encriptacion necesarios
     * @version 1.1.0
     * @param string $clave Clave de encriptacion
     * @param string $metodo_encriptacion Metodo AES etc
     * @param string $iv Palabra para encriptacion
     * @return stdClass|array obj->clave obj->metodo_encriptacion, obj->iv
     */
    private function inicializa_valores(string $clave, string $metodo_encriptacion, string $iv): stdClass|array
    {
        $conf_generales = new generales();

        $keys = array('clave','metodo_encriptacion','iv_encripta');
        $valida = (new validacion())->valida_existencia_keys(keys: $keys, registro: $conf_generales,
            valida_vacio: false);
        if(errores::$error){
            return $this->error->error(mensaje: 'Error al validar datos de configuracion generales', data: $valida);
        }

        if($clave === '') {
            $clave = $conf_generales->clave;
        }
        if($metodo_encriptacion === '') {
            $metodo_encriptacion = $conf_generales->metodo_encriptacion;
        }
        if($iv === '') {
            $iv = $conf_generales->iv_encripta;
        }

        $data = new stdClass();
        $data->clave = $clave;
        $data->metodo_encriptacion = $metodo_encriptacion;
        $data->iv = $iv;

        return $data;
    }

    /**
     * Verifica que los parametros necesarios para encriptar y desencriptar sean validos
     * @version 1.0.0
     * @return bool|array
     */
    private function verifica_datos(): bool|array
    {
        if($this->metodo_encriptacion === ''){
            return $this->error->error(mensaje: 'Error el metodo de encriptacion esta vacio',
                data: $this->metodo_encriptacion);
        }
        if($this->clave === ''){
            return $this->error->error(mensaje: 'Error el clave de encriptacion esta vacio', data: $this->clave);
        }
        if($this->iv === ''){
            return $this->error->error(mensaje: 'Error el iv de encriptacion esta vacio', data: $this->iv);
        }
        return true;
    }


}