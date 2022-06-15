<?php
/**
 * @author Martin Gamboa Vazquez
 * @version 1.2.0
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
    private string $vacio_encriptado;

    public function __construct(string $clave = '', string $iv = '', string $metodo_encriptacion = ''){
        $this->error = new errores();

        $base = $this->inicializa_datos(clave: $clave,iv:  $iv, metodo_encriptacion: $metodo_encriptacion);
        if(errores::$error){
            $error = $this->error->error(mensaje: 'Error al generar base', data: $base);
            print_r($error);
            die('Error');
        }

    }

    /**
     * Asigna los valores necesarios para la ejecucion de la clase
     * @version 1.2.0
     * @param stdClass $init obj->clave obj->metodo_encriptacion obj->iv
     * @return array|stdClass
     */
    private function asigna_valores_base(stdClass $init): array|stdClass
    {
        $keys = array('clave','metodo_encriptacion','iv');
        $valida = (new validacion())->valida_existencia_keys(keys: $keys,registro:  $init,valida_vacio: false);
        if(errores::$error){
            return $this->error->error(mensaje: 'Error al validar init', data: $valida);
        }

        if($init->clave !==''){
            $this->aplica_encriptacion = true;
        }

        $this->clave = $init->clave;
        $this->metodo_encriptacion = $init->metodo_encriptacion;
        $this->iv = $init->iv;

        $vacio_encriptado = $this->vacio_encriptado();
        if(errores::$error){
            return $this->error->error(mensaje: 'Error al generar vacio encriptado', data: $vacio_encriptado);
        }
        return $init;
    }

    /**
     * Desencripta un valor entregado
     * @version 1.2.1
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

            if(((string)$desencriptado === '') && $valor !== $this->vacio_encriptado) {
                return $this->error->error(mensaje: 'Error al desencriptar', data: $valor);
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
     * Encripta valor conforme al metodo de encriptacion md5
     * @version 1.3.1
     * @param string $valor Valor a encriptar
     * @return string
     */
    public function encripta_md5(string $valor){
        return md5($valor);
    }

    /**
     * Inicializa los atributos de la clase
     * @version 1.2.0
     * @param string $clave Clave de encriptacion
     * @param string $iv Clave de encriptacion
     * @param string $metodo_encriptacion Metodo AES
     * @return array|stdClass
     */
    private function inicializa_datos(string $clave, string $iv, string $metodo_encriptacion): array|stdClass
    {
        $init = $this->inicializa_valores(clave: $clave,iv: $iv,metodo_encriptacion: $metodo_encriptacion);
        if(errores::$error){
            return $this->error->error(mensaje: 'Error al inicializar datos', data: $init);
        }

        $base = $this->asigna_valores_base(init: $init);
        if(errores::$error){
            return $this->error->error(mensaje: 'Error al generar base', data: $base);
        }
        return $base;
    }

    /**
     * Inicializa los valores para encriptacion necesarios
     * @version 1.1.0
     * @param string $clave Clave de encriptacion
     * @param string $metodo_encriptacion Metodo AES etc
     * @param string $iv Palabra para encriptacion
     * @return stdClass|array obj->clave obj->metodo_encriptacion, obj->iv
     */
    private function inicializa_valores(string $clave, string $iv, string $metodo_encriptacion): stdClass|array
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
     * Genera el encriptado en vacio para validar que sea correcto el desencriptado
     * @version 1.2.0
     * @return array|string Valor encriptado en vacio
     */
    private function vacio_encriptado(): array|string
    {
        $vacio_encriptado = $this->encripta(valor:'');
        if(errores::$error){
            return $this->error->error(mensaje: 'Error al generar vacio encriptado', data: $vacio_encriptado);
        }
        $this->vacio_encriptado = $vacio_encriptado;
        return $vacio_encriptado;
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