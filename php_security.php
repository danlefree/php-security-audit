<?php

/**
 *  PHP Security Check Script
 *  http://php-security-audit.com/
 *
 *  This security check script will evaluate the PHP runtime environment
 *  for your configuration to determine whether any improvements could be
 *  made to your configuration.
 *
 * * * * * * *
 *
 *  Revision History
 *	
 *  2009-05-08 - 1.0 - Created
 *
 *  2009-06-10 - 1.1 - Classified security levels, added message constants
 *
 *  2009-11-23 - 1.3 - Removed "PHP_VERSION constant set" warning
 *
 *                     Note for splFileObject: (disable_classes config
 *                     directive requires lowercase)
 *
 *  2011-07-17 - 1.4 - Contributed by kaotix: Added various tweaks to make
 *                     script more compatible with Windows:
 *
 *                      - Backslashes
 *                      - OS detection
 *                      - User detection
 *
 * * * * * * *
 *	
 *  Please freely distribute this script without modification - if any
 *  improvements can be made, visit php-security-audit.com to submit
 *  your recommendation.
 *
*/


	// Application message declarations
	define( 'APP_TITLE',			'PHP Security Audit' );
	define( 'APP_DESCRIPTION',		'This audit script checks core PHP configuration, available functions, and available classes to determine potential vulnerabilities and offer configuration suggestions.' );
	define( 'APP_INSTRUCTIONS',		'If errors are reported which you do not have access to correct (as in the case of a shared hosting account), you may want to contact your hosting provider or system administrator to ensure the security of your system.' );
	
	define( 'APP_LABEL_HOSTNAME',	'Server Hostname:' );
	define( 'APP_LABEL_OS',			'Operating System:' );
	define( 'APP_LABEL_USER',		'Username:' );
	define( 'APP_LABEL_RUN_DATE',	'Date Run:' );
	
	define( 'APP_LABEL_COMMON',		'Common Exploits' );
	define( 'APP_LABEL_SHARED',		'Shared Environment Protection' );
	define( 'APP_LABEL_PARANOID',	'Locked Down Configuration' );
	
	define( 'APP_LABEL_ERROR_FEATURES',			'PHP Configuration' );
	define( 'APP_DESCRIPTION_ERROR_FEATURES',	'Update your <a href="http://us2.php.net/configuration.changes">PHP configuration</a> to correct the following issues:' );
	
	define( 'APP_LABEL_ERROR_FUNCTIONS',		'Insecure Functions' );
	define( 'APP_DESCRIPTION_ERROR_FUNCTIONS',	'Add the following to the <strong class="ms">disable_functions</strong> directive in your <a href="http://us2.php.net/configuration.changes">PHP configuration</a> to reduce your risk exposure:' );
	
	define( 'APP_LABEL_ERROR_CLASSES',			'Insecure Classes' );
	define( 'APP_DESCRIPTION_ERROR_CLASSES',	'Add the following to the <strong class="ms">disable_classes</strong> directive in your <a href="http://us2.php.net/configuration.changes">PHP configuration</a> to reduce your risk exposure:<br />Note: Configuration requires class names in lower case letters - i.e. "splfileobject"' );
	
	define( 'APP_LABEL_MESSAGES',		'Messages' );
	define( 'APP_DESCRIPTION_MESSAGES',	'' );
	
	
	// Message declarations
	define( 'MSG_BASEDIR', 'Your base directory is presently set to $$BASEDIR$$ - PHP scripts will not be able to access the file system outside of this directory.' );
	
	
	// Error declarations
	define( 'ERR_CONFIG_BASEDIR',	'Your configuration should be changed to enforce a base directory (i.e. "/var/www/") to prevent PHP from accessing other directories on the underlying filesystem.' );
	define( 'ERR_CONFIG_BASEDIR_CHDIR', 'A base directory is presently set to $$BASEDIR$$ - you should remove this directory entry to ensure that PHP scripts will not be able to access other directories by changing the working directory.' );
	define( 'ERR_CONFIG_BASEDIR_SLASH', 'A base directory is presently set to $$BASEDIR$$ - you should add a trailing "/" to ensure that PHP scripts will not be able to access the file system outside of this directory.' );
	define( 'ERR_CONFIG_ERRORS',	'Your configuration should be changed to avoid displaying error output when your scripts encounter errors as this information may be useful to a malicious user.' );
	define( 'ERR_CONFIG_EXECUTE',	'(Critical) Your configuration should be changed to restrict PHP from executing commands on the underlying system.' );
	define( 'ERR_CONFIG_INCLUDES',	'(Critical) Your configuration presently allows PHP to include files from remote webservers - this functionality should be disabled and any applications which rely upon remote file includes should be replaced immediately as there exists an extremely high potential for abuse of this feature.' );
	define( 'ERR_CONFIG_GLOBALS',	'(Critical) You must disable register_globals in your PHP configuration to prevent malicious variable manipulation.' );
	define( 'ERR_CONFIG_PHPUSER',	'PHP is running under the underlying system\'s "root" user account - this creates many possibilities for abuse. ' );
	define( 'ERR_CONFIG_PROFILE',	'Your configuration should be changed to reduce the amount of information a malicious user may gather regarding your PHP configuration.' );
	
	define( 'ERR_FUNCTION_EXECUTE',	'(Critical) This function should be disabled to prevent PHP from executing commands on the underlying system.' );
	define( 'ERR_FUNCTION_DISRUPT',	'This function should be disabled to prevent PHP scripts from disrupting other processes.' );
	define( 'ERR_FUNCTION_LOGGING',	'You should disable this function to avoid the possibility of log file tampering on your system.' );
	define( 'ERR_FUNCTION_PROFILE',	'This function should be disabled to reduce the amount of information a malicious user may gather regarding your PHP configuration. While this function must be run to generate output, some applications may include this function as part of their feature set.' );
	
	
	
	// Warning declarations
	define( 'WARN_CONFIG_PHPUSER_WIN', 'PHP is running as $$USERNAME$$ - you should ensure that this user is not an administrator on the local system as this creates many possibilites for abuse.' );
	define( 'WARN_CONFIG_UPLOAD',	'(Warning) You may want to change your configuration to prevent PHP from accepting file uploads unless this feature is absolutely necessary.' );
	define( 'WARN_FUNCTION_FILES',	'(Warning) You may want to change your configuration to disable PHP access to the underlying filesystem unless this access is absolutely necessary.' );
	
	// Awaiting implementation (need reliable mechanism for confirmation)
	define( 'ERR_VERSION',	'Your version of PHP is outdated. Exploitable vulnerabilities may exist in your present PHP installation.' );
	define( 'WARN_VERSION',	'(Warning) Your version of PHP could not be determined. While this greatly reduces the likelihood that your PHP information can be successfully profiled in mounting an attack on your system, it is recommended that you check php.net to ensure that your version of PHP is up to date.' );
	
	
	function build_output ( $section_title, $section_class, $section_description, $section_array ) {
		
		global $output_count_errors;
		
		$build_output = "";
		
		if (
			( is_array( $section_array ) ) &&
			( count( $section_array ) )
		) {
			$build_output .= "\r\n\t" . '<div class="' . $section_class . '">';
			$build_output .= "\r\n\t\t" . ' <h2>' . $section_title . '</h2>';
			$build_output .= "\r\n\t\t" . ' <p>' . $section_description . '</p>';
			$build_output .= "\r\n\t\t" . ' <ul>';
			
			foreach ( $section_array as $error_key => $error_message )
			{
				$build_output .= "\r\n\t\t\t" . '<li><strong class="ms">' . $error_key . '</strong> - ' . $error_message . '</li>';
				$output_count_errors++;
			}
			
			$build_output .= "\r\n\t\t" . ' </ul>';
			$build_output .= "\r\n\t" . '</div>';
		}
		
		return $build_output;
	}
	
	
	$insecure_features = array();
	$insecure_functions = array();
	$insecure_classes = array();
	
	$messages			= array();
	$error_features		= array();
	$error_functions	= array();
	$error_classes		= array();
	
	$output = '';
	$output_count_errors = 0;
	
	
	$flag_windows = false;
	if (
		'win' == substr(strtolower(PHP_OS), 0, 3) ||
		'cygwin' == substr(strtolower(PHP_OS), 0, 6)
	) {
		$flag_windows = true;
		$process_user = getenv('username');
	} else {
		$process_user = posix_getpwuid(posix_geteuid());
		$process_user = ($process_user) ? $process_user['name'] : '[unknown]';
	}
	
	
	$app_audit_level = '';
	if (
		$_POST &&
		array_key_exists('app_audit_level', $_POST)
	) {
		$app_audit_level = trim($_POST['app_audit_level']);
	}
	
	switch ( $app_audit_level ) {
		
		case 'paranoid':
			
			$insecure_features['expose_php']				= ERR_CONFIG_PROFILE;
			$insecure_functions['apache_child_terminate']	= ERR_FUNCTION_PROFILE;
			$insecure_functions['apache_get_modules']		= ERR_FUNCTION_PROFILE;
			$insecure_functions['apache_get_version']		= ERR_FUNCTION_PROFILE;
			$insecure_functions['apache_getenv']			= ERR_FUNCTION_PROFILE;
			$insecure_functions['get_loaded_extensions']	= ERR_FUNCTION_PROFILE;
			$insecure_functions['phpinfo']					= ERR_FUNCTION_PROFILE;
			$insecure_functions['phpversion']				= ERR_FUNCTION_PROFILE;
			
			$insecure_features['file_uploads']				= WARN_CONFIG_UPLOAD;
			$insecure_functions['chgrp']					= WARN_FUNCTION_FILES;
			$insecure_functions['chmod']					= WARN_FUNCTION_FILES;
			$insecure_functions['chown']					= WARN_FUNCTION_FILES;
			$insecure_functions['copy']						= WARN_FUNCTION_FILES;
			$insecure_functions['link']						= WARN_FUNCTION_FILES;
			$insecure_functions['mkdir']					= WARN_FUNCTION_FILES;
			$insecure_functions['rename']					= WARN_FUNCTION_FILES;
			$insecure_functions['rmdir']					= WARN_FUNCTION_FILES;
			$insecure_functions['symlink']					= WARN_FUNCTION_FILES;
			$insecure_functions['touch']					= WARN_FUNCTION_FILES;
			$insecure_functions['unlink']					= WARN_FUNCTION_FILES;
			
		case 'shared':
			
			$insecure_functions['openlog']					= ERR_FUNCTION_LOGGING;
			$insecure_functions['proc_nice']				= ERR_FUNCTION_DISRUPT;
			$insecure_functions['syslog']					= ERR_FUNCTION_LOGGING;
			
		case 'common':
			
			$insecure_classes['splFileObject'] 				= ERR_CONFIG_EXECUTE;
			
			$insecure_features['register_globals']			= ERR_CONFIG_GLOBALS;
			$insecure_features['allow_url_fopen']			= ERR_CONFIG_INCLUDES;
			$insecure_features['display_errors']			= ERR_CONFIG_ERRORS;
			
			$insecure_features['enable_dl']					= ERR_CONFIG_EXECUTE;
			$insecure_functions['apache_note']				= ERR_FUNCTION_EXECUTE;
			$insecure_functions['apache_setenv']			= ERR_FUNCTION_EXECUTE;
			$insecure_functions['dl']						= ERR_FUNCTION_EXECUTE;
			$insecure_functions['exec']						= ERR_FUNCTION_EXECUTE;
			$insecure_functions['passthru']					= ERR_FUNCTION_EXECUTE;
			$insecure_functions['pcntl_exec']				= ERR_FUNCTION_EXECUTE;
			$insecure_functions['popen']					= ERR_FUNCTION_EXECUTE;
			$insecure_functions['proc_close']				= ERR_FUNCTION_EXECUTE;
			$insecure_functions['proc_open']				= ERR_FUNCTION_EXECUTE;
			$insecure_functions['proc_get_status']			= ERR_FUNCTION_EXECUTE;
			$insecure_functions['proc_terminate']			= ERR_FUNCTION_EXECUTE;
			$insecure_functions['putenv']					= ERR_FUNCTION_EXECUTE;
			$insecure_functions['shell_exec']				= ERR_FUNCTION_EXECUTE;
			$insecure_functions['system']					= ERR_FUNCTION_EXECUTE;
			$insecure_functions['virtual']					= ERR_FUNCTION_EXECUTE;
			
			// Check PHP permissions
			if ( $flag_windows )
			{
				$error_features['PHP User Account'] = str_replace( '$$USERNAME$$', $process_user, WARN_CONFIG_PHPUSER_WIN );
			} else if ( 'root' == $process_user ) {
				$error_features['PHP User Account'] = ERR_CONFIG_PHPUSER;
			}
			
			// Check open_basedir restriction
			if ( ! ini_get('open_basedir') )
			{
				$error_features['open_basedir'] = ERR_CONFIG_BASEDIR;
			} else {
				
				$error_basedir = '';
				
				$basedirs = ( $flag_windows ) ? explode(';', ini_get('open_basedir')) : explode(':', ini_get('open_basedir'));
				
				foreach ( $basedirs as $basedir )
				{
					if ( '.' === $basedir )
					{
						$error_basedir .= ($error_basedir) ? '<br />' : '';
						$error_basedir .= str_replace( '$$BASEDIR$$', $basedir, ERR_CONFIG_BASEDIR_CHDIR );
					}
					
					if ( $flag_windows )
					{
						if ( '\\' != substr($basedir, -1) )
						{
							$error_basedir .= ($error_basedir) ? '<br />' : '';
							$error_basedir .= str_replace( '$$BASEDIR$$', $basedir, ERR_CONFIG_BASEDIR_SLASH );
						}
					} else {
						if ( '/'  != substr($basedir, -1) )
						{
							$error_basedir .= ($error_basedir) ? '<br />' : '';
							$error_basedir .= str_replace( '$$BASEDIR$$', $basedir, ERR_CONFIG_BASEDIR_SLASH );
						}
					}
				}
				
				if ( $error_basedir )
				{
					$error_features['open_basedir'] = $error_basedir;
				} else {
					$messages['Base Directory'] = str_replace( '$$BASEDIR$$', ini_get('open_basedir'), MSG_BASEDIR );
				}
			}
			
			
			// PHP version checking
			switch ( true ) {
				
				case ( defined('PHP_VERSION_ID') ):
					
					$php_version_id = PHP_VERSION_ID;
					
				case ( function_exists( 'phpversion' ) ):
					
					$php_version_id = (!$php_version_id ) ? substr(phpversion(),0,strpos(phpversion(), '-')) : $php_version_id;
					
				case ( defined('PHP_VERSION') ):
					
					$php_version_id = (!$php_version_id ) ? ($version{0} * 10000 + $version{2} * 100 + $version{4}) : $php_version_id;
					
				break;
				
				default:
					$messages_features['PHP_VERSION'] = WARN_VERSION;
				break;
			}
			
			// Check features
			if ( is_array($insecure_features) )
			{
				foreach ( $insecure_features as $feature_key => $feature_message )
				{
					if ( (bool)ini_get($feature_key) )
						$error_features[$feature_key] = $feature_message;
				}
			}
			
			// Check classes
			if ( is_array($insecure_classes) )
			{
				foreach ( $insecure_classes as $class_key => $class_message )
				{
					if ( class_exists($class_key) )
						$error_classes[$class_key] = $class_message;
				}
			}
			
			// Check functions
			if ( is_array($insecure_functions) )
			{
				foreach ( $insecure_functions as $function_key => $function_message )
				{
					if ( function_exists($function_key) )
						$error_functions[$function_key] = $function_message;
				}
			}
			
			// Build content for display
			$output .= build_output ( APP_LABEL_ERROR_FEATURES, 'error features', APP_DESCRIPTION_ERROR_FEATURES, $error_features );
			$output .= build_output ( APP_LABEL_ERROR_CLASSES, 'error classes', APP_DESCRIPTION_ERROR_CLASSES, $error_classes );
			$output .= build_output ( APP_LABEL_ERROR_FUNCTIONS, 'error functions', APP_DESCRIPTION_ERROR_FUNCTIONS, $error_functions );
			$output .= build_output ( APP_LABEL_MESSAGES, 'message', APP_DESCRIPTION_MESSAGES, $messages );
			
		break;
		
		default:
			
			// Set default content for display
			// ...
			
		break;
		
	}
	
?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
                      "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>

<title><?php if ( $output_count_errors ) echo $output_count_errors . ' Problems Identified - '; ?><?php echo APP_TITLE; ?></title>

<style type="text/css">
* {
	margin:0;
	padding:0;
}
body {
	background-color:#EFEFEF;
	font-family:Arial,sans-serif;
}
div {
	margin:10px 20px;
	padding:8px;
	-moz-border-radius:8px;
	border-radius:8px;
}
.application {
	border:solid 1px #444444;
	background-color:#F6F6F6;
}
.error {
	color:#880000;
	border:solid 1px #880000;
	background-color:#EFCCCC;
}
.message {
	color:#008800;
	border:solid 1px #008800;
	background-color:#CCEFCC;
}
ul {
	list-style-type:square;
	margin-left:20px;
}
li {
	margin-bottom:0.4em;
}
p {
	margin:0.4em 0.2em;
}
.ms {
	font-family:monospace;
}
</style>

</head>
<body>
	<div class="application">
		<h1><?php echo APP_TITLE; ?></h1>
		<hr />
		<p><?php echo APP_DESCRIPTION; ?></p>
		<p></p>
		<hr />
		<p class="ms"><strong><?php echo APP_LABEL_HOSTNAME; ?></strong> <?php echo $_SERVER['HTTP_HOST']; ?></p>
		<p class="ms"><strong><?php echo APP_LABEL_OS; ?></strong> <?php echo PHP_OS; ?></p>
		<p class="ms"><strong><?php echo APP_LABEL_USER; ?></strong> <?php echo $process_user; ?></p>
		<p class="ms"><strong><?php echo APP_LABEL_RUN_DATE; ?></strong> <?php echo date("Y-m-d H:i:s"); ?></p>
	</div>
	
	<div class="application">
		<form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post">
			<select name="app_audit_level">
				<option value="common"<?php if ($_POST && array_key_exists('app_audit_level', $_POST) && $_POST['app_audit_level'] == 'common') echo ' selected="selected"'; ?>><?php echo APP_LABEL_COMMON; ?></option>
				<option value="shared"<?php if ($_POST && array_key_exists('app_audit_level', $_POST) && $_POST['app_audit_level'] == 'shared') echo ' selected="selected"'; ?>><?php echo APP_LABEL_SHARED; ?></option>
				<option value="paranoid"<?php if ($_POST && array_key_exists('app_audit_level', $_POST) && $_POST['app_audit_level'] == 'paranoid') echo ' selected="selected"'; ?>><?php echo APP_LABEL_PARANOID; ?></option>
			</select>
			<input type="submit" value="Run Audit &gt;&gt;" />
		</form>
	</div>

<?php
	echo $output;
?>

</body>
</html>