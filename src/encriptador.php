<?php
/**
 * REG
 * Clase encriptador
 *
 * Esta clase se encarga de gestionar la encriptación y desencriptación de valores utilizando los métodos y configuraciones definidos.
 * También ofrece la funcionalidad de generación de hashes MD5.
 *
 * ## Principales características:
 * - Encripta y desencripta valores mediante `openssl_encrypt` y `openssl_decrypt`.
 * - Verifica y valida las configuraciones necesarias para realizar la encriptación.
 * - Genera valores encriptados para cadenas vacías.
 * - Proporciona un hash MD5 para valores proporcionados.
 *
 * ## Uso:
 *
 * ```php
 * use gamboamartin\encripta\encriptador;
 *
 * $clave = 'miClaveSegura';
 * $iv = '1234567890123456'; // Vector de inicialización
 * $metodo_encriptacion = 'AES-256-CBC';
 *
 * $encriptador = new encriptador($clave, $iv, $metodo_encriptacion);
 *
 * // Encriptar un valor
 * $valor = "Texto a encriptar";
 * $valor_encriptado = $encriptador->encripta($valor);
 *
 * // Desencriptar un valor
 * $valor_desencriptado = $encriptador->desencripta($valor_encriptado);
 *
 * // Generar un hash MD5
 * $hash_md5 = $encriptador->encripta_md5($valor);
 * ```
 *
 * ## Limitaciones:
 * - La clase requiere configuraciones específicas para `clave`, `iv` y `metodo_encriptacion`.
 * - El algoritmo MD5 no es adecuado para aplicaciones donde se requiere alta seguridad.
 *
 * @package gamboamartin\encripta
 * @version 6.7.0
 * @since 1.0.0
 * @author
 *   - Martin Gamboa Vazquez
 * @license MIT
 */
namespace gamboamartin\encripta;

use config\generales;
use gamboamartin\errores\errores;
use gamboamartin\validacion\validacion;
use stdClass;
use Throwable;

class encriptador{
    /**
     * Clave de encriptación utilizada para cifrar y descifrar los datos.
     *
     * Esta clave es fundamental para el proceso de encriptación y debe ser consistente
     * entre las operaciones de cifrado y descifrado.
     *
     * @var string $clave
     */
    private string $clave;

    /**
     * Indicador de si la encriptación está habilitada.
     *
     * Si es `true`, la encriptación y desencriptación serán aplicadas.
     * Si es `false`, los métodos de encriptar y desencriptar devolverán el valor original.
     *
     * @var bool $aplica_encriptacion
     */
    private bool $aplica_encriptacion = false;

    /**
     * Método de encriptación utilizado.
     *
     * Define el algoritmo de cifrado que se usará, por ejemplo, `AES-256-CBC`.
     * Este valor debe ser compatible con los algoritmos soportados por OpenSSL.
     *
     * @var string $metodo_encriptacion
     */
    private string $metodo_encriptacion;

    /**
     * Vector de inicialización (IV) para el cifrado.
     *
     * El IV es utilizado para asegurar que el mismo texto encriptado varíe cada vez,
     * aumentando la seguridad. Debe coincidir en longitud con los requisitos del método de encriptación.
     *
     * @var string $iv
     */
    private string $iv;

    /**
     * Instancia para el manejo de errores.
     *
     * Utilizada para capturar, estructurar y devolver errores detallados durante la ejecución de los métodos.
     *
     * @var errores $error
     */
    private errores $error;

    /**
     * Valor encriptado para una cadena vacía.
     *
     * Este atributo almacena el resultado de encriptar una cadena vacía (`''`).
     * Es útil para verificar desencriptaciones válidas y detectar inconsistencias.
     *
     * @var string $vacio_encriptado
     */
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
     * REG
     * Asigna valores base para la configuración de encriptación y valida su consistencia.
     *
     * Este método:
     * 1. Valida que el objeto `$init` contenga las claves necesarias (`clave`, `metodo_encriptacion`, `iv`),
     *    y que estas no estén vacías.
     * 2. Establece los valores de `clave`, `metodo_encriptacion` e `iv` en las propiedades de la clase.
     * 3. Determina si la encriptación debe aplicarse según el valor de `clave`.
     * 4. Genera el valor encriptado para una cadena vacía (`vacio_encriptado`) y lo almacena en su propiedad.
     *
     * @param stdClass $init Objeto con los valores base necesarios para la configuración:
     *                       - `clave`: Clave de encriptación.
     *                       - `metodo_encriptacion`: Método de encriptación (e.g., `AES-256-CBC`).
     *                       - `iv`: Vector de inicialización para la encriptación.
     *
     * @return array|stdClass
     *   - Retorna el objeto `$init` si todo es correcto.
     *   - Retorna un arreglo de error si ocurre algún problema durante el proceso.
     *
     * @example
     *  Ejemplo 1: Asignación de valores válidos
     *  ----------------------------------------
     *  $init = new stdClass();
     *  $init->clave = "mi_clave_secreta";
     *  $init->metodo_encriptacion = "AES-256-CBC";
     *  $init->iv = "1234567890123456";
     *
     *  $resultado = $this->asigna_valores_base($init);
     *  // $resultado contendrá el objeto $init y las propiedades de la clase se actualizarán.
     *
     * @example
     *  Ejemplo 2: Error por claves faltantes en `$init`
     *  ------------------------------------------------
     *  $init = new stdClass();
     *  $init->clave = "mi_clave_secreta";
     *  // Falta `metodo_encriptacion` e `iv`.
     *
     *  $resultado = $this->asigna_valores_base($init);
     *  // Retorna un arreglo de error indicando que faltan claves en `$init`.
     *
     * @example
     *  Ejemplo 3: Clave vacía, encriptación no se aplica
     *  --------------------------------------------------
     *  $init = new stdClass();
     *  $init->clave = "";
     *  $init->metodo_encriptacion = "AES-256-CBC";
     *  $init->iv = "1234567890123456";
     *
     *  $resultado = $this->asigna_valores_base($init);
     *  // La propiedad `aplica_encriptacion` será `false`.
     *  // $resultado contendrá el objeto $init.
     */
    private function asigna_valores_base(stdClass $init): array|stdClass
    {
        // Valida que el objeto contenga las claves requeridas
        $keys = array('clave', 'metodo_encriptacion', 'iv');
        $valida = (new validacion())->valida_existencia_keys(keys: $keys, registro: $init, valida_vacio: false);
        if (errores::$error) {
            return $this->error->error(mensaje: 'Error al validar init', data: $valida);
        }

        // Determina si aplicar la encriptación según el valor de la clave
        if ($init->clave !== '') {
            $this->aplica_encriptacion = true;
        }

        // Asigna los valores a las propiedades de la clase
        $this->clave = $init->clave;
        $this->metodo_encriptacion = $init->metodo_encriptacion;
        $this->iv = $init->iv;

        // Genera el valor encriptado para una cadena vacía
        $vacio_encriptado = $this->vacio_encriptado();
        if (errores::$error) {
            return $this->error->error(mensaje: 'Error al generar vacio encriptado', data: $vacio_encriptado);
        }

        return $init;
    }


    /**
     * REG
     * Desencripta un valor encriptado utilizando los parámetros de encriptación configurados.
     *
     * Este método:
     * 1. Verifica si la encriptación está habilitada mediante la propiedad `$this->aplica_encriptacion`.
     * 2. Valida que los datos esenciales para la encriptación estén configurados mediante el método `verifica_datos()`.
     * 3. Intenta desencriptar el valor utilizando `openssl_decrypt`.
     * 4. Devuelve el valor desencriptado o un error si el proceso falla.
     *
     * @param string $valor El valor encriptado que se desea desencriptar.
     *
     * @return string|array
     *   - Retorna el valor desencriptado si el proceso es exitoso.
     *   - Retorna un arreglo de error si ocurre algún problema durante el proceso de desencriptación.
     *
     * @example
     *  Ejemplo 1: Desencriptación exitosa
     *  -----------------------------------
     *  $this->aplica_encriptacion = true;
     *  $this->metodo_encriptacion = 'AES-256-CBC';
     *  $this->clave = 'mi_clave_secreta';
     *  $this->iv = '1234567890123456';
     *  $valor_encriptado = 'valorEncriptado123';
     *
     *  $resultado = $this->desencripta($valor_encriptado);
     *  // $resultado contendrá el valor desencriptado, por ejemplo: "miTextoOriginal".
     *
     * @example
     *  Ejemplo 2: Error al desencriptar debido a datos incompletos
     *  -----------------------------------------------------------
     *  $this->aplica_encriptacion = true;
     *  $this->metodo_encriptacion = '';
     *  $this->clave = 'mi_clave_secreta';
     *  $this->iv = '1234567890123456';
     *  $valor_encriptado = 'valorEncriptado123';
     *
     *  $resultado = $this->desencripta($valor_encriptado);
     *  // Retorna un arreglo con el error:
     *  // [
     *  //   'error' => 1,
     *  //   'mensaje' => 'Error el metodo de encriptacion esta vacio',
     *  //   'data' => '',
     *  //   ...
     *  // ]
     *
     * @example
     *  Ejemplo 3: Desencriptación deshabilitada
     *  ----------------------------------------
     *  $this->aplica_encriptacion = false;
     *  $valor_encriptado = 'valorEncriptado123';
     *
     *  $resultado = $this->desencripta($valor_encriptado);
     *  // $resultado será igual al valor original: "valorEncriptado123".
     *
     * @throws array Si ocurre un error durante la validación o el desencriptado, se devuelve un arreglo de error.
     */
    final public function desencripta(string $valor): string|array
    {
        $desencriptado = $valor;

        // Verifica si la encriptación está habilitada
        if ($this->aplica_encriptacion) {
            try {
                // Valida los parámetros necesarios para la encriptación
                $verifica = $this->verifica_datos();
                if (errores::$error) {
                    return $this->error->error(mensaje: 'Error al verificar datos', data: $verifica);
                }

                // Desencripta el valor
                $desencriptado = openssl_decrypt(
                    $valor,
                    $this->metodo_encriptacion,
                    $this->clave,
                    false,
                    $this->iv
                );
            }
            catch (Throwable $e) {
                return $this->error->error(
                    mensaje: 'Error al desencriptar',
                    data: $e,
                    es_final: true
                );
            }

            // Valida el resultado de la desencriptación
            if (((string)$desencriptado === '') && $valor !== $this->vacio_encriptado) {
                return $this->error->error(
                    mensaje: 'Error al desencriptar',
                    data: $valor,
                    es_final: true
                );
            }
        }

        return $desencriptado;
    }


    /**
     * REG
     * Encripta un valor proporcionado utilizando el método, clave y vector de inicialización configurados.
     *
     * Este método:
     * 1. Verifica si la encriptación está habilitada mediante la propiedad `$this->aplica_encriptacion`.
     * 2. Valida que los datos esenciales para la encriptación (método, clave, IV) estén correctamente configurados.
     * 3. Utiliza la función `openssl_encrypt` para encriptar el valor proporcionado.
     * 4. Retorna el valor encriptado como un string.
     *
     * @param string $valor Valor que se desea encriptar.
     *
     * @return string|array
     *   - Retorna el valor encriptado si la operación es exitosa.
     *   - Si ocurre un error durante la validación de datos, retorna un arreglo con detalles del error.
     *
     * @example
     *  Ejemplo 1: Encriptación habilitada con datos configurados
     *  ----------------------------------------------------------
     *  $this->aplica_encriptacion = true;
     *  $this->metodo_encriptacion = 'AES-256-CBC';
     *  $this->clave = 'mi_clave_secreta';
     *  $this->iv = '1234567890123456';
     *
     *  $valor = 'Texto a encriptar';
     *  $resultado = $this->encripta($valor);
     *  // $resultado contendrá un string con el texto encriptado.
     *
     * @example
     *  Ejemplo 2: Encriptación deshabilitada
     *  -------------------------------------
     *  $this->aplica_encriptacion = false;
     *
     *  $valor = 'Texto a encriptar';
     *  $resultado = $this->encripta($valor);
     *  // $resultado será igual al valor original: 'Texto a encriptar'.
     *
     * @example
     *  Ejemplo 3: Error en la configuración de datos
     *  ---------------------------------------------
     *  $this->aplica_encriptacion = true;
     *  $this->metodo_encriptacion = ''; // Método no configurado
     *  $this->clave = 'mi_clave_secreta';
     *  $this->iv = '1234567890123456';
     *
     *  $valor = 'Texto a encriptar';
     *  $resultado = $this->encripta($valor);
     *  // Retorna un arreglo de error:
     *  // [
     *  //   'error' => 1,
     *  //   'mensaje' => 'Error al verificar datos',
     *  //   'data' => [...],
     *  //   ...
     *  // ]
     */
    final public function encripta(string $valor): string|array
    {
        $encriptado = $valor;

        // Verifica si la encriptación está habilitada
        if ($this->aplica_encriptacion) {

            // Valida los datos esenciales para la encriptación
            $verifica = $this->verifica_datos();
            if (errores::$error) {
                return $this->error->error(
                    mensaje: 'Error al verificar datos',
                    data: $verifica
                );
            }

            // Encripta el valor utilizando openssl_encrypt
            $encriptado = openssl_encrypt(
                $valor,
                $this->metodo_encriptacion,
                $this->clave,
                false,
                $this->iv
            );
        }

        // Retorna el valor encriptado o el valor original si la encriptación está deshabilitada
        return $encriptado;
    }


    /**
     * REG
     * Genera un hash MD5 a partir de un valor proporcionado.
     *
     * Este método toma un string como entrada y devuelve el hash MD5 correspondiente.
     * Es útil para situaciones donde se requiere un identificador único o un valor hash
     * para propósitos de comparación, almacenamiento o verificación.
     *
     * **Nota:** MD5 no es seguro para propósitos criptográficos modernos debido a su vulnerabilidad
     * a colisiones. Debe usarse solo en casos donde la seguridad no sea una preocupación crítica.
     *
     * @param string $valor El valor que se desea encriptar utilizando el algoritmo MD5.
     *
     * @return string Retorna el hash MD5 del valor proporcionado.
     *
     * @example
     *  Ejemplo 1: Generar un hash MD5
     *  --------------------------------
     *  $valor = "miTextoSeguro";
     *  $resultado = $this->encripta_md5($valor);
     *  // $resultado contendrá algo como: "ef96c69e8b3c50bb927a8c6d8cd302f5"
     *
     * @example
     *  Ejemplo 2: Generar un hash MD5 con un string vacío
     *  --------------------------------------------------
     *  $valor = "";
     *  $resultado = $this->encripta_md5($valor);
     *  // $resultado será: "d41d8cd98f00b204e9800998ecf8427e"
     */
    final public function encripta_md5(string $valor): string
    {
        return md5($valor);
    }


    /**
     * REG
     * Inicializa y configura los valores necesarios para la encriptación.
     *
     * Este método:
     * 1. Llama a `inicializa_valores` para obtener los valores base de configuración (clave, método de encriptación e IV).
     * 2. Valida y asigna los valores base utilizando `asigna_valores_base`.
     * 3. Retorna el objeto con los valores configurados o un error si ocurre algún problema durante el proceso.
     *
     * @param string $clave               Clave para la encriptación. Si está vacía, se utilizará un valor predeterminado.
     * @param string $iv                  Vector de inicialización para la encriptación. Si está vacío, se utilizará un valor predeterminado.
     * @param string $metodo_encriptacion Método de encriptación (e.g., `AES-256-CBC`). Si está vacío, se utilizará un valor predeterminado.
     *
     * @return array|stdClass
     *   - Retorna un objeto `stdClass` con los valores inicializados si todo es correcto.
     *   - Retorna un arreglo de error si ocurre algún problema durante el proceso.
     *
     * @example
     *  Ejemplo 1: Inicialización con valores personalizados
     *  -----------------------------------------------------
     *  $clave = "mi_clave_secreta";
     *  $iv = "1234567890123456";
     *  $metodo_encriptacion = "AES-256-CBC";
     *
     *  $resultado = $this->inicializa_datos($clave, $iv, $metodo_encriptacion);
     *  // $resultado contendrá un objeto con los valores inicializados:
     *  // {
     *  //     "clave": "mi_clave_secreta",
     *  //     "metodo_encriptacion": "AES-256-CBC",
     *  //     "iv": "1234567890123456"
     *  // }
     *
     * @example
     *  Ejemplo 2: Uso de valores predeterminados
     *  -----------------------------------------
     *  $clave = "";
     *  $iv = "";
     *  $metodo_encriptacion = "";
     *
     *  $resultado = $this->inicializa_datos($clave, $iv, $metodo_encriptacion);
     *  // Si los valores predeterminados están configurados correctamente, se retornará:
     *  // {
     *  //     "clave": "valor_predeterminado_clave",
     *  //     "metodo_encriptacion": "AES-256-CBC",
     *  //     "iv": "1234567890123456"
     *  // }
     *
     * @example
     *  Ejemplo 3: Error en la inicialización
     *  -------------------------------------
     *  $clave = "";
     *  $iv = "";
     *  $metodo_encriptacion = "";
     *
     *  // Si faltan configuraciones en los valores predeterminados, se generará un error:
     *  $resultado = $this->inicializa_datos($clave, $iv, $metodo_encriptacion);
     *  // [
     *  //     'error' => 1,
     *  //     'mensaje' => 'Error al inicializar datos',
     *  //     'data' => ...
     *  // ]
     */
    private function inicializa_datos(string $clave, string $iv, string $metodo_encriptacion): array|stdClass
    {
        // Inicializa los valores base de encriptación
        $init = $this->inicializa_valores(clave: $clave, iv: $iv, metodo_encriptacion: $metodo_encriptacion);
        if (errores::$error) {
            return $this->error->error(mensaje: 'Error al inicializar datos', data: $init);
        }

        // Asigna los valores base y valida la configuración
        $base = $this->asigna_valores_base(init: $init);
        if (errores::$error) {
            return $this->error->error(mensaje: 'Error al generar base', data: $base);
        }

        return $base;
    }


    /**
     * REG
     * Inicializa y valida los valores de configuración necesarios para la encriptación.
     *
     * Este método:
     * 1. Verifica la existencia de los datos de configuración esenciales en la clase `generales`.
     * 2. Asigna valores predeterminados desde la configuración global si los parámetros `$clave`, `$iv`
     *    o `$metodo_encriptacion` están vacíos.
     * 3. Retorna un objeto con los valores finales listos para su uso.
     *
     * @param string $clave              Clave de encriptación proporcionada. Si está vacía, se asigna desde `generales`.
     * @param string $iv                 Vector de inicialización (IV) proporcionado. Si está vacío, se asigna desde `generales`.
     * @param string $metodo_encriptacion Método de encriptación proporcionado. Si está vacío, se asigna desde `generales`.
     *
     * @return stdClass|array
     *   - Retorna un objeto `stdClass` con los valores configurados para `clave`, `iv` y `metodo_encriptacion`.
     *   - En caso de error durante la validación de los datos, retorna un arreglo con los detalles del error.
     *
     * @example
     *  Ejemplo 1: Configuración manual de valores
     *  ------------------------------------------------
     *  $clave = 'mi_clave_secreta';
     *  $iv = '1234567890123456';
     *  $metodo_encriptacion = 'AES-256-CBC';
     *
     *  $resultado = $this->inicializa_valores($clave, $iv, $metodo_encriptacion);
     *  // Retorna un objeto:
     *  // $resultado->clave => 'mi_clave_secreta'
     *  // $resultado->iv => '1234567890123456'
     *  // $resultado->metodo_encriptacion => 'AES-256-CBC'
     *
     * @example
     *  Ejemplo 2: Uso de valores predeterminados de configuración global
     *  -------------------------------------------------------------------
     *  // Asumiendo que en la clase `generales` existen los siguientes valores:
     *  // $conf_generales->clave = 'clave_global';
     *  // $conf_generales->metodo_encriptacion = 'AES-256-CBC';
     *  // $conf_generales->iv_encripta = 'iv_global_123456';
     *
     *  $clave = '';
     *  $iv = '';
     *  $metodo_encriptacion = '';
     *
     *  $resultado = $this->inicializa_valores($clave, $iv, $metodo_encriptacion);
     *  // Retorna un objeto:
     *  // $resultado->clave => 'clave_global'
     *  // $resultado->iv => 'iv_global_123456'
     *  // $resultado->metodo_encriptacion => 'AES-256-CBC'
     *
     * @example
     *  Ejemplo 3: Error en la configuración global
     *  --------------------------------------------
     *  // Si en la clase `generales` faltan las claves requeridas (`clave`, `metodo_encriptacion`, `iv_encripta`),
     *  // el método retorna un arreglo de error.
     *
     *  $clave = '';
     *  $iv = '';
     *  $metodo_encriptacion = '';
     *
     *  $resultado = $this->inicializa_valores($clave, $iv, $metodo_encriptacion);
     *  // Retorna un arreglo:
     *  // [
     *  //   'error' => 1,
     *  //   'mensaje' => 'Error al validar datos de configuracion generales',
     *  //   'data' => [...],
     *  //   ...
     *  // ]
     */
    private function inicializa_valores(string $clave, string $iv, string $metodo_encriptacion): stdClass|array
    {
        // Carga la configuración global
        $conf_generales = new generales();

        // Verifica la existencia de claves esenciales en la configuración global
        $keys = array('clave', 'metodo_encriptacion', 'iv_encripta');
        $valida = (new validacion())->valida_existencia_keys(keys: $keys, registro: $conf_generales, valida_vacio: false);
        if (errores::$error) {
            return $this->error->error(
                mensaje: 'Error al validar datos de configuracion generales',
                data: $valida
            );
        }

        // Asigna valores predeterminados si los parámetros están vacíos
        if ($clave === '') {
            $clave = $conf_generales->clave;
        }
        if ($metodo_encriptacion === '') {
            $metodo_encriptacion = $conf_generales->metodo_encriptacion;
        }
        if ($iv === '') {
            $iv = $conf_generales->iv_encripta;
        }

        // Construye el objeto con los valores finales
        $data = new stdClass();
        $data->clave = $clave;
        $data->metodo_encriptacion = $metodo_encriptacion;
        $data->iv = $iv;

        return $data;
    }


    /**
     * REG
     * Genera el valor encriptado para una cadena vacía y lo almacena en la propiedad `$this->vacio_encriptado`.
     *
     * Este método:
     * 1. Llama al método `encripta` con una cadena vacía (`''`) como valor.
     * 2. Verifica si ocurrió un error durante el proceso de encriptación.
     * 3. Si no hay errores, almacena el resultado en `$this->vacio_encriptado`.
     * 4. Retorna el valor encriptado generado o un arreglo de error si la encriptación falla.
     *
     * @return array|string
     *   - Retorna el valor encriptado de una cadena vacía como un `string`.
     *   - Si ocurre un error durante la encriptación, retorna un arreglo con los detalles del error.
     *
     * @example
     *  Ejemplo 1: Generar un valor encriptado vacío con encriptación habilitada
     *  ------------------------------------------------------------------------
     *  $this->aplica_encriptacion = true;
     *  $this->metodo_encriptacion = 'AES-256-CBC';
     *  $this->clave = 'mi_clave_secreta';
     *  $this->iv = '1234567890123456';
     *
     *  $resultado = $this->vacio_encriptado();
     *  // $resultado contendrá el valor encriptado de una cadena vacía.
     *
     * @example
     *  Ejemplo 2: Error en la configuración de encriptación
     *  -----------------------------------------------------
     *  $this->aplica_encriptacion = true;
     *  $this->metodo_encriptacion = '';
     *  $this->clave = 'mi_clave_secreta';
     *  $this->iv = '1234567890123456';
     *
     *  $resultado = $this->vacio_encriptado();
     *  // Retorna un arreglo de error:
     *  // [
     *  //   'error' => 1,
     *  //   'mensaje' => 'Error al generar vacio encriptado',
     *  //   'data' => [...],
     *  //   ...
     *  // ]
     *
     * @example
     *  Ejemplo 3: Encriptación deshabilitada
     *  -------------------------------------
     *  $this->aplica_encriptacion = false;
     *
     *  $resultado = $this->vacio_encriptado();
     *  // $resultado será igual a una cadena vacía, ya que la encriptación está deshabilitada.
     */
    private function vacio_encriptado(): array|string
    {
        // Genera el valor encriptado para una cadena vacía
        $vacio_encriptado = $this->encripta(valor: '');

        // Verifica si ocurrió un error durante la encriptación
        if (errores::$error) {
            return $this->error->error(
                mensaje: 'Error al generar vacio encriptado',
                data: $vacio_encriptado
            );
        }

        // Almacena el resultado en la propiedad correspondiente
        $this->vacio_encriptado = $vacio_encriptado;

        // Retorna el valor encriptado
        return $vacio_encriptado;
    }


    /**
     * REG
     * Verifica que los datos esenciales para realizar la encriptación estén correctamente configurados.
     *
     * Este método:
     * 1. Valida que el atributo `$metodo_encriptacion` no esté vacío.
     * 2. Valida que el atributo `$clave` (clave de encriptación) no esté vacío.
     * 3. Valida que el atributo `$iv` (vector de inicialización) no esté vacío.
     *
     * Si cualquiera de estos atributos está vacío, se genera un error a través de `$this->error->error()` y
     * se retorna un arreglo con los detalles del error.
     *
     * @return true|array
     *   - Retorna `true` si todos los atributos necesarios están configurados correctamente.
     *   - Retorna un `array` de error si alguna validación falla, incluyendo un mensaje y los datos correspondientes.
     *
     * @example
     *  Ejemplo 1: Verificación exitosa de datos de encriptación
     *  ---------------------------------------------------------
     *  $this->metodo_encriptacion = 'AES-256-CBC';
     *  $this->clave = 'mi_clave_secreta';
     *  $this->iv = '1234567890123456';
     *
     *  $resultado = $this->verifica_datos();
     *  // $resultado será `true`, ya que todos los datos están correctamente configurados.
     *
     * @example
     *  Ejemplo 2: Método de encriptación vacío
     *  ----------------------------------------
     *  $this->metodo_encriptacion = '';
     *  $this->clave = 'mi_clave_secreta';
     *  $this->iv = '1234567890123456';
     *
     *  $resultado = $this->verifica_datos();
     *  // Retorna un arreglo con el error:
     *  // [
     *  //   'error' => 1,
     *  //   'mensaje' => 'Error el metodo de encriptacion esta vacio',
     *  //   'data' => '',
     *  //   ...
     *  // ]
     *
     * @example
     *  Ejemplo 3: Clave de encriptación vacía
     *  ---------------------------------------
     *  $this->metodo_encriptacion = 'AES-256-CBC';
     *  $this->clave = '';
     *  $this->iv = '1234567890123456';
     *
     *  $resultado = $this->verifica_datos();
     *  // Retorna un arreglo con el error:
     *  // [
     *  //   'error' => 1,
     *  //   'mensaje' => 'Error el clave de encriptacion esta vacio',
     *  //   'data' => '',
     *  //   ...
     *  // ]
     *
     * @example
     *  Ejemplo 4: Vector de inicialización vacío
     *  ------------------------------------------
     *  $this->metodo_encriptacion = 'AES-256-CBC';
     *  $this->clave = 'mi_clave_secreta';
     *  $this->iv = '';
     *
     *  $resultado = $this->verifica_datos();
     *  // Retorna un arreglo con el error:
     *  // [
     *  //   'error' => 1,
     *  //   'mensaje' => 'Error el iv de encriptacion esta vacio',
     *  //   'data' => '',
     *  //   ...
     *  // ]
     */
    private function verifica_datos(): true|array
    {
        if ($this->metodo_encriptacion === '') {
            return $this->error->error(
                mensaje: 'Error el metodo de encriptacion esta vacio',
                data: $this->metodo_encriptacion,
                es_final: true
            );
        }
        if ($this->clave === '') {
            return $this->error->error(
                mensaje: 'Error el clave de encriptacion esta vacio',
                data: $this->clave,
                es_final: true
            );
        }
        if ($this->iv === '') {
            return $this->error->error(
                mensaje: 'Error el iv de encriptacion esta vacio',
                data: $this->iv,
                es_final: true
            );
        }
        return true;
    }



}