<?php

/**
 * @autores: Emilio Rodríguez & Pablo Martínez
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package moodle ACyT
 *
 * Authentication Plugin: Servidor CAS - Gobierno de La Rioja
 *
 * 2012-03-06  Fin de edición.
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
}

require_once($CFG->libdir.'/authlib.php');
// Utilizamos la clase CAS del plugin CAS, para no duplicarlo en la llamada

// Si está instalado el plugin de CAS, utilizamos su Objeto phpCAS
// y si no el nuestro.
$auths = get_plugin_list('auth');
if(@$auths["cas"]){
	require_once($CFG->dirroot.'/auth/cas/CAS/CAS.php');
}else{
	require_once($CFG->dirroot.'/auth/acyt/CAS.php');
}	
/**
 * Plugin para autentificación CAS - Gobierno de La Rioja.
 */
class auth_plugin_acyt extends auth_plugin_base {

    /**
     * Constructor.
     */
	
    function auth_plugin_acyt() {
        $this->authtype = 'acyt';
        $this->config = get_config('auth/acyt');
    }
	
    function prevent_local_passwords() {
        return true;
    }	

    /**
     * Returns true if the username and password work or don't exist and false
     * if the user exists and the password is wrong.
     *
     * @param string $username The username
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
	 
    function user_login ($username, $password) {
		// Si el usuario tiene como método de autenticación únicamente CAS-acyt e intenta entrar con usuario-contraseña de multiauth.
		// Lo redireccionamos al index, aunque se podría poner una página intermedia
		//redirect('/error.php?cod=99');
		//return true;
	
		$authCAS = optional_param('authCAS', '', PARAM_RAW);
        if ($authCAS != 'CAS'){
            return false;
        }
		return phpCAS::isAuthenticated();
    }
	
    /**
     * Logout from the CAS
     *
     */
    function prelogout_hook() {
        global $CFG;
		
		// Llamamos a la función que nos recupera el objeto phpCAS
		$this->connect_checkCAS(false);	
		$entrada_CAS = phpCAS::isAuthenticated();

		if ($entrada_CAS){
			// URL 
			$backurl = $CFG->wwwroot;
			
			// Llamamos a la función que nos recupera el objeto phpCAS
			$this->connect_checkCAS(true);
			// Hacemos logout de todo el sistema CAS
			phpCAS::logout(array('service'=>$backurl));
		}
    }	
	
    /**
     * Función que abre la conexión CAS
     * Si la conexión ya está abierta, no hace nada (eso pensamos)
     * 
     */
    function connect_checkCAS($forzar_entrada) {
        // Conectamos con CAS
		// Utilizamos el código del simple_client.php, bajado de la web del CAS
		// Full Hostname of your CAS Server
		$cas_host = $this->config->hostname;
		// Context of the CAS Server
		$cas_context = $this->config->baseuri;
		// Port of your CAS server. Normally for a https server it's 443
		$cas_port = intval($this->config->port);
		$cas_real_hosts = array (
			$this->config->hostname
		);

		global $PHPCAS_CLIENT;
		if (!is_object($PHPCAS_CLIENT)) {
			// Initialize phpCAS
			phpCAS::client(CAS_VERSION_2_0, $cas_host, $cas_port, $cas_context, false);
		}
		
		if($forzar_entrada){
			phpCAS::setNoCasServerValidation();
			// force CAS authentication
			phpCAS::forceAuthentication();	
		}
    }
	
	
	
	
    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return false;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return false;
    }	

	
    /**
     * Authentication choice (CAS or other)
     * Redirection to the CAS form or to login/index.php
     * for other authentication
     */
    function loginpage_hook() {
        global $frm;
        global $CFG;
		global $DB;
        global $SESSION, $OUTPUT, $PAGE;
		
        $site = get_site();
        $CASform = get_string('CASform', 'auth_acyt');
        $username = optional_param('username', '', PARAM_RAW);
		
        if (!empty($username)) {
            if (isset($SESSION->wantsurl) && (strstr($SESSION->wantsurl, 'ticket') ||
                                              strstr($SESSION->wantsurl, 'NOCAS'))) {
                unset($SESSION->wantsurl);
            }
            return;
        }

        // Return if CAS enabled and settings not specified yet
		if (empty($this->config->hostname)) {
            return;
        }	
	
		// Generating the URLS for the local cas example services for proxy testing
		if ( isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on'){
			$curbase = 'https://'.$_SERVER['SERVER_NAME'];
		}else{
			$curbase = 'http://'.$_SERVER['SERVER_NAME'];
		}
		if ($_SERVER['SERVER_PORT'] != 80 && $_SERVER['SERVER_PORT'] != 443)
			$curbase .= ':'.$_SERVER['SERVER_PORT'];

		$curdir = dirname($_SERVER['REQUEST_URI'])."/";
		
        if ($this->config->multiauth) {
            $authCAS = optional_param('authCAS', '', PARAM_RAW);
			
			if ($authCAS == 'NOCAS') {
                return;
            }

            // Show authentication form for multi-authentication
            // test pgtIou parameter for proxy mode (https connection
            // in background from CAS server to the php server)
            if ($authCAS != 'CAS' && !isset($_GET['pgtIou'])) {
				$PAGE->set_url('/auth/acyt/auth.php');
                $PAGE->navbar->add($CASform);
                $PAGE->set_title("$site->fullname: $CASform");
                $PAGE->set_heading($site->fullname);
                echo $OUTPUT->header();
                include($CFG->dirroot.'/auth/acyt/cas_form.html');
                echo $OUTPUT->footer();
                exit();
            }
		}		 
		
		// Llamamos a la función que nos recupera el objeto phpCAS
		$this->connect_checkCAS(true);
		
		//$frm->username=phpCAS::getUser();
		//$frm->username="admin";
		
		$dni = phpCAS::getUser();
		//$frm->password=$this->config->password;
		
		// TODO: Bug: Sacar de user_info_field el fieldid correspondiente al campo dni
		$table = 'user_info_data';
		$select = "LOWER(data) = LOWER('" . $dni . "')"; //is put into the where clause
		$result = $DB->get_records_select($table,$select);
		
		// Si hay más de un usuario con el mismo DNI, cogería el primero
		foreach ($result as $i => $value) {
			$userid = @intval($value->{'userid'});
			break;
		}
		
		if(@$userid){

			// Usuario admin
			//$user = $DB->get_record('user', array('username'=>$frm->username, 'mnethostid'=>$CFG->mnet_localhost_id));
			// Usuario DNI del certificado
			$user = $DB->get_record('user', array('id'=>$userid, 'mnethostid'=>$CFG->mnet_localhost_id));

			$frm->username=$user->username;
			$frm->password="";
			
			if(@$user){
				return true;
			} else {
				// No esta autentificado
				//redirect($CFG->wwwroot.'/index.php');
				$msg_error = "usuario: " . (String)$frm->username . " pass: " . (String)$frm->password;
				redirect($CFG->wwwroot.'/index.php', "El usuario no se ha autentificado", 5);
			}
		} else {
			// El usuario con el DNI especificado en el certificado no es un usuario de Moodle o la contraseña no coincide.
			// Políticas de acceso, altas, etc.
			//redirect($CFG->wwwroot.'/index.php');
			//redirect($CFG->wwwroot.'/index.php', "El usuario no existe en Moodle", 5);
			//$cod_error = "Error en Moodle";

            include($CFG->dirroot.'/auth/acyt/alta_usuario.php');

			exit();
		}
	}
	
    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        return null;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    function config_form($config, $err, $user_fields) {
        include "config.html";
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config($config) {

        // CAS settings
        if (!isset($config->hostname)) {
            $config->hostname = '';
        }
        if (!isset($config->port)) {
            $config->port = '';
        }
        if (!isset($config->baseuri)) {
            $config->baseuri = '';
        }
        if (!isset($config->multiauth)) {
            $config->multiauth = '';
        }

		$this->pluginconfig = "auth/acyt";
		
        // save CAS settings
        set_config('hostname', trim($config->hostname), $this->pluginconfig);
        set_config('port', trim($config->port), $this->pluginconfig);
        set_config('baseuri', trim($config->baseuri), $this->pluginconfig);
        set_config('multiauth', $config->multiauth, $this->pluginconfig);

        return true;
    }
}


