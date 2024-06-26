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
     * POR DOCUMENTAR EN WIKI FINAL REV
     * Asigna los valores base necesarios para la encriptación.
     *
     * Esta función es parte de la clase Encriptador y se usa para configurar los valores base
     * necesarios para la encriptación y desencriptación. Los valores base incluyen la 'clave'
     * que se usará para encriptar/desencriptar los datos, el 'metodo_encriptacion'
     * que determina qué algoritmo de encriptación se debe utilizar y el 'iv' que es el
     * vector de inicialización requerido por algunos modos de operación de cifrado.
     *
     * También genera un valor para 'vacio_encriptado' que se usa para manejar los valores vacíos
     * durante el proceso de encriptación/desencriptación.
     *
     * Si se proporciona una 'clave' no vacía, 'aplica_encriptacion' se establece en true
     * lo que significa que la encriptación se aplicará en los datos.
     *
     * @param stdClass $init Un objeto con las claves 'clave', 'metodo_encriptacion' e 'iv'
     * @return array|stdClass Retorna el mismo objeto $init en caso de éxito, o un objeto de error
     *                        sí se encuentra una anomalía durante la validación o la generación
     *                        del valor 'vacio_encriptado'.
     *
     * @throws errores si los parámetros proporcionados no son válidos o si el valor
     *                   'Vacio_encriptado' no se puede generar.
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
     * TOTAL
     * Desencripta el valor proporcionado.
     *
     * La función desencripta recibe un string, realiza la verificación de datos y si no hay ningún error procede a
     * desencriptar el valor.
     * Si se presenta un error durante la verificación de datos o la desencriptación, se devuelve un error.
     * Si el valor desencriptado es una cadena vacía y el valor proporcionado no está vacío, entonces también se
     * devuelve un error.
     * @param string $valor El valor a desencriptar.
     * @return string|array El valor desencriptado o un array de error, si algo falla.
     * @version 4.3.0
     * @url https://github.com/gamboamartin/encripta/wiki/src.encriptador.desencripta.6.7.0
     */
    final public function desencripta(string $valor): string|array
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
                return $this->error->error(mensaje: 'Error al desencriptar',data:  $e, es_final: true);
            }

            if(((string)$desencriptado === '') && $valor !== $this->vacio_encriptado) {
                return $this->error->error(mensaje: 'Error al desencriptar', data: $valor, es_final: true);
            }

        }
        return $desencriptado;
    }

    /**
     * POR DOCUMENTAR EN WIKI FINAL REV
     * Encripta un valor conforme al metodo cargado en generales
     *
     * Esta función toma un valor de entrada, verifica los datos y si no hay ningún error, encripta el valor.
     * Si se presenta un error durante la verificación de datos o la encriptación, se devuelve un error.
     *
     * @param string $valor Valor a encriptar
     *
     * @return string|array Retorna el valor encriptado o un arreglo de error si algo falla
     * @version 4.4.0
     */
    final public function encripta(string $valor): string|array
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
     * POR DOCUMENTAR EN WIKI FINAL REV
     * Función encripta_md5
     *
     * Esta función se encarga de encriptar una cadena dada utilizando el algoritmo md5.
     *
     * @param string $valor La cadena que se desea encriptar.
     * @return string Retorna la cadena encriptada en formato md5.
     *
     * @example
     * ```
     * $textoEncriptado = encripta_md5("Hola mundo");
     * echo $textoEncriptado; // Imprime algo similar a: fc5e038d38a57032085441e7fe7010b0
     * ```
     *
     * @throws errores Si el parámetro de entrada no es una cadena.
     *
     * @note Por favor, ten en cuenta que md5 no es un algoritmo de encriptación segura,
     * y su uso no se recomienda para almacenar contraseñas u otra información sensible.
     * @version 6.5.0
     */
    final public function encripta_md5(string $valor): string
    {
        return md5($valor);
    }

    /**
     * POR DOCUMENTAR EN WIKI FINAL REV
     * Inicializa los datos utilizados para la encriptación.
     *
     * @param string $clave El string que se utiliza como clave para la encriptación.
     * @param string $iv Vector de inicialización para el método de encriptación.
     * @param string $metodo_encriptacion El método de encriptación a utilizar.
     *
     * @return array|stdClass Retorna los valores inicializados si es exitoso,
     *                        o un objeto de error en caso contrario.
     *
     * @version 6.4.0
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
     * POR DOCUMENTAR EN WIKI FINAL REV
     * Esta función inicia los valores relacionados con la encriptación.
     * Se toma como referencia la configuración general para determinar los valores iniciales de la clave,
     * el vector de inicialización (iv), y el método de encriptación. Si estos valores vienen en los parámetros de
     * la función, se utilizan esos valores. Si no, se toman los valores por defecto de la configuración general.
     * Esta función regresa un objeto con los valores de clave, vector de inicialización y método de encriptación.
     *
     * @param string $clave - Clave de encriptación
     * @param string $iv - Vector de inicialización para la encriptación
     * @param string $metodo_encriptacion - Método de encriptación a utilizar
     *
     * @return stdClass|array - Objeto con los datos de la encriptación o arreglo con el error si existió alguno
     * durante la operación
     *
     * @version 4.2.0
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
     * POR DOCUMENTAR EN WIKI FINAL REV
     * Genera una representación encriptada de una cadena vacía
     *
     * Esta función encripta una cadena vacía y devuelve el resultado. Se usa principalmente
     * para comparaciones en otras operaciones de encriptación de este sistema. Si la encriptación
     * no está habilitada en la configuración del sistema, simplemente devuelve una cadena vacía.
     *
     * @return string|array  Representación encriptada de una cadena vacía o un mensaje de error si la
     *                 encriptación falla.
     *
     * @version 4.5.0
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
     *  TOTAL
     * Verifica si los datos son válidos para la encriptación.
     * Comprueba si el método de encriptación, la clave y el IV (vector de inicialización)
     * no están vacíos. En caso afirmativo, devuelve un error, en caso contrario, devuelve true.
     *
     * @return true|array Retorna true si todos los datos son válidos.
     * Retorna un array con mensaje de error en caso contrario.
     * @version 4.1.0
     * @url https://github.com/gamboamartin/encripta/wiki/src.encriptador.verifica_datos.6.7.0
     */
    private function verifica_datos(): true|array
    {
        if($this->metodo_encriptacion === ''){
            return $this->error->error(mensaje: 'Error el metodo de encriptacion esta vacio',
                data: $this->metodo_encriptacion, es_final: true);
        }
        if($this->clave === ''){
            return $this->error->error(mensaje: 'Error el clave de encriptacion esta vacio', data: $this->clave
                , es_final: true);
        }
        if($this->iv === ''){
            return $this->error->error(mensaje: 'Error el iv de encriptacion esta vacio', data: $this->iv,
                es_final: true);
        }
        return true;
    }


}