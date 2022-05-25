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


    /**
     */
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
        $this->assertEquals('afnn4IH/j6/t9Kiz0OkOBw==', $resultado);

        errores::$error = false;

    }

}

