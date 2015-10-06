<?php
// must be run within Dokuwiki
if (!defined('DOKU_INC')) die();
/**
 * Two Factor Action Plugin
 *
 * @author Mike Wilmes mwilmes@avc.edu
 * Big thanks to Daniel Popp and his Google 2FA code (authgoogle2fa) as a 
 * starting reference.
 *
 * Overview:
 * The plugin provides for two opportunities to perform two factor 
 * authentication. The first is on the main login page, via a code provided by 
 * an external authenticator. The second is at a separate prompt after the 
 * initial login. By default, all modules will process from the second login,
 * but a module can subscribe to accepting a password from the main login when
 * it makes sense, because the user has access to the code in advance.
 * 
 * If a user only has configured modules that provide for login at the main 
 * screen, the code will only be accepted at the main login screen for 
 * security purposes.
 *
 * Modules will be called to render their configuration forms on the profile 
 * page and to verify a user's submitted code. If any module accepts the 
 * submitted code, then the user is granted access.
 *
 * Each module may be used to transmit a message to the user that their 
 * account has been logged into. One module may be used as the default 
 * transmit option. These options are handled by the parent module.
 */

// Load the authmod class. This will facilitate loading in child modules.
require_once(dirname(__FILE__).'/authmod.php');

class action_plugin_twofactor extends DokuWiki_Action_Plugin {
	public $success = false;
	private $attribute = null;

	public function __construct() {
		$this->loadConfig();
		// Load the attribute helper if GA is active or not requiring use of email to send the OTP.
		$requireAttribute = $this->getConf("enable") === 1;
		$this->attribute = $requireAttribute ? $this->loadHelper('attribute', 'Attribute plugin required!') : null;		
		
		// Now figure out what modules to load and load them.				
		$available = Twofactor_Auth_Module::listModules();
		$desired = explode(',', $this->getConf('modules'));
		$unavailable = array_diff($desired, $available);
		if (count($unavailable) > 0) {
			msg('At least one requested module is not present.' . ' ' . implode(', ', $unavailable), -1);
		}
		$loading = array_intersect($available, $desired);
		$this->modules = Twofactor_Auth_Module::loadModules($loading);
		$failed = array_diff($loading, array_keys($this->modules));
		if (count($failed) > 0) {
			msg('At least one loaded module did not have a properly named class.' . ' ' . implode(', ', $failed), -1);
		}

		// Sanity check.
		$this->success = (!$requireAttribute || ($this->attribute && $this->attribute->success)) && count($this->modules) > 0);
		
		// This is a check flag to verify that the user's profile is being updated.
		$this->modifyProfile = false;
	}

	/**
	 * return some info
	 */
	function getInfo(){
		return array(
            'author' => 'Mike Wilmes',
            'email'  => 'mwilmes@avc.edu',
            'date'   => '2015-09-04',
            'name'   => 'TwoFactor Plugin',
            'desc'   => 'This plugin provides for two factor authentication using extensible modules.',
            'url'    => 'http://www.dokuwiki.org/plugin:twofactor',
		);
	}

    /**
     * Registers the event handlers.
     */
    function register(&$controller)
    {
        if($this->getConf("enable") === 1 && $this->success) {
			$firstlogin = false;
			foreach ($this->modules as $mod) {
				$firstlogin |= $mod->canAuthLogin();
			}
			if ($firstlogin) {
				$controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'twofactor_login_form', array());				
			}
			$controller->register_hook('AUTH_LOGIN_CHECK', 'BEFORE', $this, 'twofactor_before_auth_check', array());
			$controller->register_hook('AUTH_LOGIN_CHECK', 'AFTER', $this, 'twofactor_after_auth_check', array());
            $controller->register_hook('TPL_CONTENT_DISPLAY', 'BEFORE', $this, 'twofactor_prompt_otp', array());
            $controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT', 'BEFORE', $this, 'twofactor_profile_form', array());
            $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'twofactor_action_process_handler', array());
            $controller->register_hook('AUTH_USER_CHANGE', 'AFTER', $this, 'twofactor_process_changes', array());
        }
    }

    /**
     * Handles the login form rendering.
     */
    function twofactor_login_form(&$event, $param) {
		$twofa_form = form_makeTextField('otp', '', $this->getLang('twofactor_login'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
        $pos = $event->data->findElementByAttribute('type', 'submit');
        $event->data->replaceElement($pos-1, $twofa_form);
    }

    /**
     * Handles the profile form rendering.  Displays user manageable settings.
     */
    function twofactor_profile_form(&$event, $param) {
		$optinout = $this->getConf("optinout");
		$optstate = $optinout == 'mandatory' ? 'in' : ($this->attribute ? $this->attribute->get("twofactor","state") : '');
		$available = false;
		foreach ($this->modules as $mod) {
			$available |= $mod->canUse();
		}
		
		// If the user is being redirected here because of mandatory two factor, then display a message saying so.
		if (!$available && $optinout == 'mandatory') {
			msg($this->getLang('twofactor_mandatory'), -1);
		}

		global $USERINFO;
		// Get the location just above the submit buttons.
		$pos = $event->data->findElementByAttribute('type', 'submit') - 1;		
		// Add the checkbox to opt in and out, only if optinout is not mandatory.
		if ($this->getConf("optinout") != 'mandatory') {
			$value = $optstate;
			if (!$this->attribute || !$value) {  // If there is no personal setting for optin, the default is based on the wiki default.
				$value = $this->getConf("optinout") == 'optout';
			}
			$twofa_form = form_makeCheckboxField('optinout', '1', $this->getLang('twofactor_optin'), '', 'block', $value=='in'?array('checked'=>'checked'):array());
			$event->data->insertElement($pos++, $twofa_form);
		}

		// TODO: Make this AJAX so that the user does not have to keep clicking 
		// submit them Update Profile!
		//Loop through all modules and render the profile components.
		if ($optstate == 'in') {			
			$parts = array();
			foreach ($this->modules as $mod){
				$parts = array_merge($mod->renderProfileForm(), $parts);
			}
			foreach($parts as $part) {
				$event->data->insertElement($pos++, $part);
			}
		}
    }

    /**
     * Sets a flag if we are working with the profile. This ensures that extra data is only updated when the profile is being worked on.
     */
    function twofactor_verify_in_profile(&$event, $param) {
		// Check if this is the condition we are trying to monitor.
		$this->modifyProfile = $event->data == 'profile';
		return true;
	}

    /**
     * Action process redirector.  If logging out, processes the logout
     * function.  If visiting the profile, sets a flag to confirm that the
     * profile is being viewed in order to enable OTP attribute updates.
     */
	function twofactor_action_process_handler(&$event, $param){
		if ($event->data == 'logout') {
			$this->twofactor_logout();
			return true;
		}
		elseif ($event->data == 'profile') {
			return $this->twofactor_verify_in_profile($event, $param);
		}
		return true;
	}

    /**
     * Logout this session from two factor authentication.  Purge any existing
     * OTP from the user's attributes.
     */
    function twofactor_logout() {
		if ($this->attribute) {
			$this->attribute->del("twofactor","otp");
		}
		unset($_SESSION[DOKU_COOKIE]['plugin']['twofactor']['clearance']);
	}

    /**
     * See if the current session has passed two factor authentication.
     * @return bool - true if the session as successfully passed two factor
     *      authentication.
     */
    function twofactor_getClearance() {
		return isset($_SESSION[DOKU_COOKIE]['plugin']['twofactor']['clearance'])  && $_SESSION[DOKU_COOKIE]['plugin']['twofactor']['clearance'] === true;
	}

    /**
     * Flags this session as having passed two factor authentication.
     * @return bool - returns true on successfully granting two factor clearance.
     */
    function twofactor_grantClearance() {
		// Purge the otp code as a security measure.
		$this->attribute->del("twofactor","otp");
		return $_SESSION[DOKU_COOKIE]['plugin']['twofactor']['clearance']=true;
	}

    /**
     * If the conditions are right, process any updates to this module's attributes.
     */
    function twofactor_process_changes(&$event, $param) {
		// If the plugin is disabled, then exit.
		if ($this->getConf("enable") !== 1 || !$this->success) { return; }
		// If this is a modify event that succeeded, we are ok.
		if ($event->data['type'] == 'modify' && in_array($event->data['modification_result'], array(true, 1)) && $this->modifyProfile) {
			$changed = false;
			global $INPUT, $USERINFO;
			// Process opt in/out.
			if ($this->getConf("optinout") != 'mandatory') {
				$oldoptinout = $this->attribute->get("twofactor","state") === 'in'?'in':'out';
				$optinout = $INPUT->bool('optinout', false)?'in':'out';
				if ($oldoptinout != $optinout) {
					$this->attribute->set("twofactor","state", $optinout);
					$changed = true;
				}
			}
			// Update module settings.
			$sendotp = null;
			foreach ($this->modules as $name=>$mod){
				$result = $mod->processProfileForm();
				$changed |= $result !== false && $result !== 'failed';
				switch($changed) {
					case 'verified':
						// Remove used OTP.
						$this->attribute->del("twofactor","otp");
						msg($this->getLang('twofactor_passedsetup') . ' ' . $name, 1);
						break;
					case 'failed':
						msg($this->getLang('twofactor_failedsetup') . ' ' . $name, -1);
						break;
					case 'otp':
						if (!$sendotp) {
							$sendotp = $mod;
						}						
				}
			}
			// Send OTP if requested.
			if ($sendotp) {
				$this->twofactor_send_otp($sendotp);
			}

			// Update change status if changed.
			if ($changed) {
				msg($this->getLang('twofactor_updated'), 1);
				// TODO: get the profile page to return if any two factor changes are made.
			}
		}
		return ;
	}

    /**
     * Handles the authentication check. Screens Google Authenticator OTP, if available.
     */
    function twofactor_before_auth_check(&$event, $param) {
		global $ACT;
		
		// If two factor is disabled, then there is nothing to do here.
		if ($this->getConf("enable") !== 1) return; 
		
		// Only operate if this is a login.
		//if ($ACT !== 'login') return;
		
		// If there is no supplied username, then there is nothing to check at this time.
		if (!$event->data['user']) { return; }
		
		$user = $_SERVER['REMOTE_USER'] != '' ? $_SERVER['REMOTE_USER'] : $event->data['user'];
		// If there is no active user name, then purge our two factor clearance token.
		if ($_SERVER['REMOTE_USER'] == '') {
			$this->twofactor_logout();
		}

		// If the user still has clearance, then we can skip this.		
		if ($this->twofactor_getClearance()) { return; }
		
		$workingMods = array_filter($this->modules, function ($mod) { return $mod->canAuthLogin(); });
		if (count($workingMods) > 0 && $user) {  
			$otp = $INPUT->str('otp');
			$result = false;
			if ($otp) {
				// Check for any modules that support OTP at login and are ready for use.
				foreach ($this->modules as $name=>$mod){
					if ($mod->canAuthLogin() && $mod->canUse()) {
						$result |= $mod->processLogin($otp);
						if ($result) { 
							// The OTP code was valid.
							$this->twofactor_grantClearance();
							return;					
						}
					}
				}
				global $lang;
				msg($lang['badlogin'], -1);
				$event->preventDefault();
				return;
			}
			else { // No GA OTP was supplied.
				// If the user has an alternative two factor configured, then allow it to be used.
				// Otherwise fail.				
				$useableMods = array_filter($this->modules, function ($mod) { return !$mod->canAuthLogin() && $mod->canUse(); });
				if (count($useableMods) == 0) {
					// There is no other two factor option, and this user did not supply a GA OTP code.
					// Revoke the logon.
					msg($this->getLang('twofactor_mustusega'), -1);
					$event->preventDefault();
					return;
				}
			}					
		}
		
		// Check to see if the user has configured any module for use.
		$useableMods = array_filter($this->modules, function ($mod) { return $mod->canUse(); });
		if (count($useableMods) == 0) {
			// If the user has not configured either option and two factor is not mandatory, then grant clearance.				
			if ($this->getConf("optinout") != 'mandatory') {
				//There is no two factor configured for this user and it is not mandatory. Give clearance.
				$this->twofactor_grantClearance();
			}	
			// Otherwise this is mandatory.  Stop the default action, and set ACT to profile so the user can configure their two factor.
			$ACT = 'profile';
		}		
    }

    /**
     * @param $event
     * @param $param
     */
    function twofactor_after_auth_check(&$event, $param) {
		// If two factor is disabled, then there is nothing to do here.
		if ($this->getConf("enable") !== 1) return; 
		
		// Skip this if not logged in or already two factor authenticated.
		$twofactor = $this->twofactor_getClearance();
		if ($_SERVER['REMOTE_USER'] == '' || $twofactor === true) { return; }

		global $INPUT, $ACT;
		// If the user is trying to logout, then we will allow this.
		if ($ACT == 'logout') { return; }

		$optinout = $this->getConf("optinout");
		$optstate = $this->attribute ? $this->attribute->get("twofactor","state") : '';
		$enable = $this->getConf("enable") && // The module is enabled AND...
			((!$optinout === 'optin' || $optstate === 'in') // Opt-in is off OR the user has opted in
			|| // OR...
			($optinout === 'optout' && $optstate !== 'out') // Opt-out is on AND the user has not opted out
			|| // OR...
			$optinout === 'mandatory'); // User must participate.
		if ($enable) {
			// Check to see if the user has configured any module for use.
			$useableMods = array_filter($this->modules, function ($mod) { return $mod->canUse(); });
			if (count($useableMods) == 0) {
				// If the user has not configured either option and two factor is not mandatory, then grant clearance.				
				if ($this->getConf("optinout") != 'mandatory') {
					//There is no two factor configured for this user and it is not mandatory. Give clearance.
					$this->twofactor_grantClearance();
				}	
				// Otherwise this is mandatory.  Stop the default action, and set ACT to profile so the user can configure their two factor.
				$ACT = 'profile';
				return;
			}		
			
			// See if the user is quitting OTP.  We don't call it logoff because we don't want the user to think they are logged in!
			// This has to be checked before the template is started.
			if ($INPUT->has('otpquit')) {
				// Redirect to logoff.
				$event->preventDefault();
				$event->stopPropagation();
				$ACT = 'logout';
				return;
			}

			// If a OTP has been submitted by the user, then verify the OTP.
			// If verified, then grant clearance and continue normally.
			$otp = $INPUT->str('otpcode');
			$otppresent = $this->attribute->exists("twofactor","otp");
			if ($otppresent) {
				list($myotp, $expires) = $this->attribute->get("twofactor","otp");
			}
			if ($otp && !$INPUT->has('resend')) {
				if ($otp != $myotp || time() > $expires) {
					// The OTP is wrong or expired.  Inform the user.
					msg($this->getLang('twofactor_invalidotp') ,-1);
				}
				else {
					// The OTP was valid.  Flag past this block.
					$this->twofactor_grantClearance();
					return;
				}
			}
			
			// Check if the user asked to generate and resend the OTP.
			if ($INPUT->has('resend')) {
				if	($INPUT->has('useall')) {
					$defaultMod = null;
				}
				else {
					$defaultMod = $this->attribute ? $this->attribute->get("twofactor","defaultmod") : null;
				}
				// At this point, try to send the OTP.
				$this->twofactor_send_otp($defaultMod);
			}
		}
	}
	
	/**
     * Handles the email and text OTP options.
	 * NOTE: The user will be technically logged in at this point.  This module will rewrite the
	 * page with the prompt for the OTP until validated or the user logs out.
     */
    function twofactor_prompt_otp(&$event, $param) {
		// Skip this if not logged in or already two factor authenticated.
		$twofactor = $this->twofactor_getClearance();
		if ($_SERVER['REMOTE_USER'] == '' || $twofactor === true) { return; }
		
		// Setup some availability variables.
		$optinout = $this->getConf("optinout");
		$optstate = $this->attribute ? $this->attribute->get("twofactor","state") : '';
		$enable = $this->getConf("enable") && // The module is enabled AND...
			((!$optinout === 'optin' || $optstate === 'in') // Opt-in is off OR the user has opted in
			|| // OR...
			($optinout === 'optout' && $optstate !== 'out')) // Opt-out is on AND the user has not opted out
			|| // OR...
			$optinout === 'mandatory'; // User must participate.
		if ($enable){ // User logged in, two factor required, but not completed.

			// If we are here, the user has configured some sort two factor 
			// mechanism.  At a minimum, if they had login authentication 
			// setup but not OTP, then their login would have failed.
			// That means that we will try to process the login via OTP.
			// If the user cannot sign in using OTP, see if they need to be 
			// directed to the profile screen to setup two factor.
			global $ACT;
			// Check to see if the user has configured any module for use.
			$useableMods = array_filter($this->modules, function ($mod) { return $mod->canUse(); });
			if (count($useableMods) == 0 && $ACT == 'profile') {
				// We are heading to the profile page because nothing is setup.  Good.
				return;
			}
			
			// Ensure the OTP exists and is still valid. If we need to, send a OTP.
			$otppresent = $this->attribute->exists("twofactor","otp");
			if ($otppresent) {
				list($myotp, $expires) = $this->attribute->get("twofactor","otp");
			}
			if (!$otppresent || time() > $expires) {
				// At this point, try to send the OTP.
				$defaultMod = $this->attribute ? $this->attribute->get("twofactor","defaultmod") : null;
				$this->twofactor_send_otp($defaultMod);
			}

			// Generate the form to login.
			// If we are here, then only provide options to accept the OTP or to logout.		
    		global $lang;
			$form = new Doku_Form(array('id' => 'otp_setup'));
			$form->startFieldset($this->getLang('twofactor_otplogin'));
			$form->addElement(form_makeTextField('otpcode', '', $this->getLang('twofactor_otplogin'), '', 'block', array('size'=>'50', 'autocomplete'=>'off')));
			$form->addElement(form_makeButton('submit', '', $this->getLang('btn_submit')));
			$form->addElement(form_makeTag('br'));
			$form->addElement(form_makeCheckboxField('useall', '1', $this->getLang('twofactor_useallmods'), '', 'block'));
			$form->addElement(form_makeTag('br'));
			$form->addElement(form_makeButton('submit', '', $this->getLang('btn_resend'), array('name'=>'resend')));
			$form->addElement(form_makeButton('submit', '', $this->getLang('btn_quit'), array('name'=>'otpquit')));
			$form->endFieldset();
			$output = '<div class="centeralign">'.NL.$form->getForm().'</div>'.NL;
			$event->data = '<div class="centeralign">'.NL.$form->getForm().'</div>'.NL;
		}
    }

    /**
     * Transmits a One-Time Password (OTP) configured modules.
     * If $module is set to a specific instance, that instance will be used to 
	 * send the OTP. If not supplied or null, then all configured modules will 
	 * be used to send the OTP. $module can allso be an array of selected 
	 * modules.
     * @return mixed - true if successfull to all attempted tramsmission 
	 *     modules, false if all failed, and a number of how many successes 
	 *     if only some modules failed.
     */
    function twofactor_send_otp($module = null) {
		if ($module === null) {
			$module = array_filter($this->modules, function ($x){return $x->canUse()});
		}
		if (!is_array($module)) {
			$module = array($module);
		}		
		// Generate the OTP code.
		$characters = '0123456789';
		$otp = '';
		for ($index = 0; $index < $this->getConf('otplength'); ++$index) {
			$otp .= $characters[rand(0, strlen($characters) - 1)];
		}
		// Create the message.
		$message = str_replace('$otp', $otp, $this->getConf('otpcontent'));
		// Pick the delivery method.
		$success = 0;
		foreach($module as $mod) {
			if ($mod->canTransmitMessage()) {
				$success += $mod->transmitMessage($message) ? 1 : 0;
			}
		}
		
		// If partially successful, store the OTP code and the timestamp the OTP expires at.
		if ($success > 0) {
			$this->attribute->set("twofactor","otp", array($otp, time() + $this->getConf('otpexpiry') * 60));
		}
		return $success == 0 ? false : ($success == count($mod) ? true : $success);
	}
}
