<?php

	if (!defined('MOODLE_INTERNAL')) 
	{
		die('Direct access to this script is forbidden.');
	}
	
	$moodleBaseURL = $CFG->wwwroot;
	
	@date_default_timezone_set('UTC');	

	function startsWith($haystack, $needle)
	{
		$haystack = strtolower($haystack);
		$needle = strtolower($needle);
		
		$length = strlen($needle);
		return (substr($haystack, 0, $length) === $needle);
	}

	require_once($CFG->libdir.'/authlib.php');

	class auth_plugin_sso extends auth_plugin_base 
	{

        /**
         * Constructor.
         */
        function auth_plugin_sso() {
            $this->authtype = 'sso';
        }

		function user_login($username, $password) 
		{
		   return false;
		}

		function can_reset_password() 
		{
			return false;
		}

		function can_signup() 
		{
			return false;
		}

		function can_confirm() 
		{
			return false;
		}

		function can_change_password() 
		{
			return false;
		}

		function loginpage_hook() {
			global $CFG, $USER, $SESSION;

			if ($_SERVER['REQUEST_METHOD'] === 'GET' && !empty($_GET['u']) && !empty($_GET['t']) && !empty($_GET['h']) && !empty($_GET['r'])) 
			{	
				$secret = $CFG->passwordsaltmain;
		
				$username = $_GET['u'];
				$time = $_GET['t'];
				$hash = $_GET['h'];
				$redirect = urldecode($_GET['r']);		
				
				$strToHash = $username . $time . $redirect . $secret;
				$expectedHash = sha1($strToHash);	
				
				if (strcmp($hash,$expectedHash) !== 0)
				{	
					add_to_log(SITEID, 'collabco_sso', 'error', 'auth.php', "Bad hash: " . $username);
					error_log('[client '.getremoteaddr()."]  $moodleBaseURL  Bad hash:  $username  " . $_SERVER['HTTP_USER_AGENT']);
					return false;
				}
				
				if (startsWith($redirect, "http://") || startsWith($redirect, "www."))
				{
					add_to_log(SITEID, 'collabco_sso', 'error', 'auth.php', "Illegal redirect: " . $redirect);
					error_log('[client '.getremoteaddr()."]  $moodleBaseURL  Illegal redirect:  $redirect  " . $_SERVER['HTTP_USER_AGENT']);
					return false;
				}
			
				if (isloggedin() && !isguestuser()) 
				{
				   redirect($moodleBaseURL . "/" . $redirect);
				   return false;
				}
				
				$timestamp = DateTime::createFromFormat('d-m-Y-H-i', $time);
				
				if ((abs(time() - $timestamp->getTimestamp()) / 60) < 10) 
				{			
					$user = get_complete_user_data('username', $username, $CFG->mnet_localhost_id);
											
					if ($user) 
					{
						add_to_log(SITEID, 'collabco_sso', 'sso login event', "auth.php" , "SSO login: " . $username, 0, $user->id);
						
						$auth = empty($user->auth) ? 'manual' : $user->auth;  // use manual if auth not set
						
						if (!empty($user->suspended)) {
							add_to_log(SITEID, 'collabco_sso', 'error', 'auth.php', "Suspended login: " . $username, 0, $user->id);
							error_log('[client '.getremoteaddr()."]  $moodleBaseURL  Suspended Login:  $username  ".$_SERVER['HTTP_USER_AGENT']);
							return false;
						}
						
						if ($auth=='nologin' or !is_enabled_auth($auth)) {
							add_to_log(SITEID, 'collabco_sso', 'error', 'auth.php', "Disabled login: " . $username, 0, $user->id);
							error_log('[client '.getremoteaddr()."]  $moodleBaseURL  Disabled Login:  $username  ".$_SERVER['HTTP_USER_AGENT']);
							return false;
						}		

						complete_user_login($user);
						
						if (user_not_fully_set_up($USER)) 
						{
						   $urltogo = $moodleBaseURL . "/user/edit.php";
						} 
						else
						{
						   $urltogo = $moodleBaseURL . "/" . $redirect;
						}
						
						redirect($urltogo);
					}
					else
					{
						return false;
					}
				}
				else
				{
					echo "this single sign on link has expired";
				}
			}
		}

		function config_form($config, $err, $user_fields) 
		{
			global $CFG, $OUTPUT;
			echo $OUTPUT->notification('There are no config options for this plugin');
			return;
		}
	}
