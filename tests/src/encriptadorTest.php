<?php
namespace tests\controllers;

use gamboamartin\encripta\encriptador;
use gamboamartin\errores\errores;
use gamboamartin\test\liberator;
use gamboamartin\test\test;
use JsonException;
use stdClass;


class encriptadorTest extends test {
    public errores $errores;
    private stdClass $paths_conf;
    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->errores = new errores();
        $this->paths_conf = new stdClass();
        $this->paths_conf->generales = '/var/www/html/administrador/config/generales.php';
        $this->paths_conf->database = '/var/www/html/administrador/config/database.php';
        $this->paths_conf->views = '/var/www/html/administrador/config/views.php';
    }

    public function test_asigna_valores_base(): void
    {


        errores::$error = false;
        $en = new encriptador();
        $en = new liberator($en);
        $init = new stdClass();
        $resultado = $en->asigna_valores_base($init);
        $this->assertTrue(errores::$error);
        $this->assertIsArray( $resultado);
        $this->assertStringContainsStringIgnoringCase( 'Error al validar init',$resultado['mensaje']);

        errores::$error = false;

        $init = new stdClass();
        $init->clave = 'xxx xx xx';
        $init->metodo_encriptacion = 'aes-256-cbc';
        $init->iv = 'WtYTL1/M8jfstw==';
        $resultado = $en->asigna_valores_base($init);
        $this->assertNotTrue(errores::$error);
        $this->assertIsObject( $resultado);

        errores::$error = false;
    }
    public function test_desencripta(): void
    {


        errores::$error = false;
        $en = new encriptador();
        $valor = '';
        $encriptado = $en->encripta($valor);
        if(errores::$error){
            $error = (new errores())->error('Error al encriptar', $encriptado);
            print_r($error);
            exit;
        }
        $resultado = $en->desencripta($encriptado);


        $this->assertNotTrue(errores::$error);
        $this->assertIsString( $resultado);
        $this->assertEquals( '',$resultado);

        errores::$error = false;
        $valor = 'test';
        $encriptado = $en->encripta($valor);
        if(errores::$error){
            $error = (new errores())->error('Error al encriptar', $encriptado);
            print_r($error);
            exit;
        }
        $resultado = $en->desencripta($encriptado);
        $this->assertNotTrue(errores::$error);
        $this->assertIsString( $resultado);
        $this->assertEquals( 'test',$resultado);
        errores::$error = false;



    }

    public function test_encripta(): void
    {


        errores::$error = false;
        $en = new encriptador();
        $valor = '';
        $resultado = $en->encripta($valor);
        $this->assertNotTrue(errores::$error);
        $this->assertIsString( $resultado);

        errores::$error = false;

        $valor = 'prueba';
        $resultado = $en->encripta($valor);
        $this->assertNotTrue(errores::$error);
        $this->assertEquals('WrnhAI/ra34HC1co+Ziohg==', $resultado);

        errores::$error = false;

    }

    public function test_encripta_md5(): void
    {
        errores::$error = false;

        $en = new encriptador();
        $valor = '';
        $resultado = $en->encripta_md5($valor);
        $this->assertNotTrue(errores::$error);
        $this->assertIsString($resultado);
        $this->assertEquals('d41d8cd98f00b204e9800998ecf8427e', $resultado);

        errores::$error = false;

        $valor = 'prueba';
        $resultado = $en->encripta_md5($valor);
        $this->assertNotTrue(errores::$error);
        $this->assertIsString($resultado);
        $this->assertEquals('c893bad68927b457dbed39460e6afd62', $resultado);

        errores::$error = false;
    }

    public function test_inicializa_datos(): void
    {
        errores::$error = false;
        $en = new encriptador();
        $en = new liberator($en);
        $clave = '';
        $iv = '';
        $metodo_encriptacion = '';
        $resultado = $en->inicializa_datos($clave, $iv, $metodo_encriptacion);
        $this->assertNotTrue(errores::$error);
        $this->assertEquals('WtYTL1/M8jdszw==', $resultado->iv);
        $this->assertEquals('aes-256-cbc', $resultado->metodo_encriptacion);

        errores::$error = false;

        $clave = 'zzz';
        $iv = '';
        $metodo_encriptacion = '';
        $resultado = $en->inicializa_datos($clave, $iv, $metodo_encriptacion);
        $this->assertNotTrue(errores::$error);
        $this->assertEquals('WtYTL1/M8jdszw==', $resultado->iv);
        $this->assertEquals('aes-256-cbc', $resultado->metodo_encriptacion);
        $this->assertEquals('zzz', $resultado->clave);
        errores::$error = false;
    }

    public function test_inicializa_valores(): void
    {

        errores::$error = false;
        $en = new encriptador();
        $en = new liberator($en);
        $clave = '';
        $metodo_encriptacion = '';
        $iv = '';
        $resultado = $en->inicializa_valores($clave, $metodo_encriptacion, $iv);
        $this->assertNotTrue(errores::$error);
        $this->assertIsObject( $resultado);
        $this->assertEquals( 'administrador',$resultado->clave);
        $this->assertEquals( 'aes-256-cbc',$resultado->metodo_encriptacion);
        $this->assertEquals( 'WtYTL1/M8jdszw==',$resultado->iv);

        errores::$error = false;
        $clave = 'a';
        $metodo_encriptacion = '';
        $iv = '';
        $resultado = $en->inicializa_valores($clave, $metodo_encriptacion, $iv);
        $this->assertNotTrue(errores::$error);
        $this->assertIsObject( $resultado);
        $this->assertEquals( 'a',$resultado->clave);
        $this->assertEquals( 'aes-256-cbc',$resultado->metodo_encriptacion);
        $this->assertEquals( 'WtYTL1/M8jdszw==',$resultado->iv);

        errores::$error = false;
    }

    public function test_verifica_datos(): void
    {
        errores::$error = false;
        $en = new encriptador();
        $en = new liberator($en);
        $resultado = $en->verifica_datos();
        $this->assertNotTrue(errores::$error);
        $this->assertIsBool( $resultado);
        $this->assertTrue( $resultado);

        errores::$error = false;
        $en = new encriptador(clave: 'x');
        $en = new liberator($en);
        $resultado = $en->verifica_datos();
        $this->assertNotTrue(errores::$error);
        $this->assertIsBool( $resultado);
        $this->assertTrue( $resultado);

    }


    public function test_vacio_encriptado(): void
    {

        errores::$error = false;
        $en = new encriptador();
        $en = new liberator($en);
        $encriptado = $en->vacio_encriptado();
        $this->assertNotTrue(errores::$error);
        $this->assertIsString( $encriptado);
        $this->assertEquals('PHDA/NloYgF1lc+UHzxaUw==', $encriptado);
        errores::$error = false;
    }

}

