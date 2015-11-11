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

 if(!defined('DOKU_TWOFACTOR_PLUGIN_IMAGES')) define('DOKU_TWOFACTOR_PLUGIN_IMAGES',DOKU_BASE.'lib/plugins/twofactor/images/');

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
		$available = Twofactor_Auth_Module::_listModules();		
		$allmodules = Twofactor_Auth_Module::_loadModules($available);
		$failed = array_diff($available, array_keys($allmodules));
		if (count($failed) > 0) {
			msg('At least one loaded module did not have a properly named class.' . ' ' . implode(', ', $failed), -1);
		}
		$this->modules =array_filter($allmodules, function($obj) {return $obj->getConf('enable') == 1;});

		// Sanity check.
		//msg("Number of loaded twofactor modules: ".count($this->modules));
		$this->success = (!$requireAttribute || ($this->attribute && $this->attribute->success)) && count($this->modules) > 0;
		
		// This is a check flag to verify that the user's profile is being updated.
		$this->modifyProfile = false;
	}

	/**
	 * return some info
	 */
	public function getInfo(){
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
    public function register(&$controller)
    {
        if($this->getConf("enable") === 1 && $this->success) {
			$firstlogin = false;
			foreach ($this->modules as $mod) {
				$firstlogin |= $mod->canAuthLogin();
			}
			if ($firstlogin) {
				$controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'twofactor_login_form', array());				
			}
			// Provide user settings in profile.
            $controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT', 'BEFORE', $this, 'twofactor_profile_form', array());
			// Ensures we are in the user profile.
            $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'twofactor_action_process_handler', array());
			// Updates user settings. Ensures that the settings ceom from the profile using a flag passed by the above hook.
            $controller->register_hook('AUTH_USER_CHANGE', 'BEFORE', $this, 'twofactor_process_changes', array());
			// If the user supplies a token code at login, checks it before logging the user in.
			$controller->register_hook('AUTH_LOGIN_CHECK', 'BEFORE', $this, 'twofactor_before_auth_check', array());
			// Atempts to process the second login if the user hasn't done so already.
			$controller->register_hook('AUTH_LOGIN_CHECK', 'AFTER', $this, 'twofactor_after_auth_check', array());
            // Ensures the user has passed the second login after logged in or displays a challenge screen.
			$controller->register_hook('TPL_CONTENT_DISPLAY', 'BEFORE', $this, 'twofactor_prompt_otp', array());
			// Hook the AJAX handler so we can process twofactor in a more user-friendly manner.
			$controller->register_hook('AJAX_CALL_UNKNOWN', 'BEFORE', $this,'twofactor_process_ajax');
        }
    }

    /**
     * Handles the login form rendering.
     */
    public function twofactor_login_form(&$event, $param) {
		$twofa_form = form_makeTextField('otp', '', $this->getLang('twofactor_login'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
        $pos = $event->data->findElementByAttribute('type', 'submit');
        $event->data->replaceElement($pos-1, $twofa_form);
    }

    /**
     * Handles the profile form rendering.  Displays user manageable settings.
     */
    public function twofactor_profile_form(&$event, $param) {
		if ($this->getConf("enable") !== 1 || !$this->success) { return; }

		$optinout = $this->getConf("optinout");
		$optstate = $optinout == 'mandatory' ? 'in' : ($this->attribute ? $this->attribute->get("twofactor","state") : '');
		$available = false;
		foreach ($this->modules as $mod) {
			$available |= $mod->canUse();
		}
		
		// If the user is being redirected here because of mandatory two factor, then display a message saying so.
		if (!$available && $optinout == 'mandatory') {
			msg($this->getLang('mandatory'), -1);
		}

		global $USERINFO;
		/*
		// Get the location just above the submit buttons.
		$pos = $event->data->findElementByAttribute('type', 'submit') - 1;	
		//msg(print_r($event->data, true));
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
			//echo serialize($this->modules).'<hr>';
			foreach ($this->modules as $mod){
				if ($mod->getConf("enable") == 1) {
					$output = $mod->renderProfileForm();
					//echo serialize($output).'<hr>';
					$parts = array_merge($output, $parts);
					//echo serialize($parts).'<hr><hr>';
				}
			}
			foreach($parts as $part) {
				$event->data->insertElement($pos++, $part);
			}
			// Last output a field for the default module, if more than one can be used.
			$useableMods = array();
			foreach($this->modules as $name=>$mod) {
				if(!$mod->canAuthLogin() && $mod->canUse()) { 
					$useableMods[$mod->getLang("name")] = $mod; 
				}
			}
			// If there is more than one choice, have the user select the default.
			if (count($useableMods) > 1) {
				$defaultMod = $this->attribute->exists("twofactor","defaultmod") ? $this->attribute->get("twofactor","defaultmod") : null;				
				$modList = array_merge(array($this->getLang('useallotp')), array_keys($useableMods));
				$twofa_form = form_makeListboxField('default_module', $modList, $defaultMod, $this->getLang('defaultmodule'), '', 'block');			 
				$event->data->insertElement($pos++, $twofa_form);
			}
		}
		*/
		// Create a fieldset for twofactor options.
		$event->data->startFieldset($this->getLang('profile_label'));
		// This sets up the CSS styles.
		$event->data->getElementAt(-1)['id'] = 'twofactor';
		$event->data->addElement("<div class=\"option\" onclick=\"toggle_option(this);\">");
		$event->data->addElement("<img class=\"dropdown\" alt=\"$alt\" src=\"".DOKU_TWOFACTOR_PLUGIN_IMAGES."arrowrt.png\" />");
		$event->data->addElement("<b>".$this->getLang('profile_general_label')."</b>");
		$event->data->addElement("<img class=\"configured\" alt=\"$alt\" src=\"".DOKU_TWOFACTOR_PLUGIN_IMAGES."green.png\" />");
		$event->data->addElement("</div>");
		$event->data->addElement("<div class=\"settings\">");
		$event->data->addElement("</div>");
		foreach ($this->modules as $mod){
			if ($mod->getConf("enable") == 1) {
				$output = $mod->renderProfileForm();
				foreach($output as $part) {
					$event->data->addElement($part);
				}
			}
		}
		$event->data->addElement("<input type=\"sumbit\" name=\"".$this->getLang('save')."\" onclick=\"return twofactor_save_settings();\" />");
		$event->data->endFieldset();
    }
	
	private function _profile_header($name, $legend) {
		$html = "<img class=\"configured\" alt=\"$alt\" src=\"".DOKU_TWOFACTOR_PLUGIN_IMAGES."arrowrt.png\" />";
		$html += "<div class=\"settings\"></div>";
		$html += "</div>";
		return $html;
	}

    /**
     * AJAX processing. Allows for twofactor to be configured without constant screen refreshes.
     */
    public function twofactor_process_ajax(&$event, $param) {
		if ($event->data !== 'plugin_twofactor') {
			return;
		}
		//no other ajax call handlers needed
		$event->stopPropagation();
		$event->preventDefault();	

		$json = new JSON();		
		
		global $INPUT;
		$module = $INPUT->str('mod','');		
		if (!array_key_exists($module, $this->modules) && $module != 'twofactor') {
			$response = null;
		}
		else {
			$mod = $module != 'twofactor' ? $this->modules[$module] : $this;
			$request = $INPUT->str('req','');
			$data = $json->decode($INPUT->str('params'));
			$response = $mod->process_ajax($request, $data);
		}
		
		header('Content-Type: application/json');
		echo $json->encode($response);
		}
		
	/**
	 * This is the AJAX entry point of data specific to the twofactor module itself.
	 */
	public function process_ajax($request, &$data) {
		
	}
	
	
    /**
     * Action process redirector.  If logging out, processes the logout
     * function.  If visiting the profile, sets a flag to confirm that the
     * profile is being viewed in order to enable OTP attribute updates.
     */
	public function twofactor_action_process_handler(&$event, $param){
		global $USERINFO;
		if ($event->data == 'logout') {
			$this->_logout();
			return true;
		}
		elseif ($event->data == 'profile') {
			return $this->_verify_in_profile($event, $param);
		}
		elseif ($this->getConf("optinout") == 'mandatory' && $this->get_clearance() == false) {
			// Not logged in but going 'somewhere'
			if ($event->data != 'login' && $USERINFO == null) {
				//msg("Redirect to login");
				// If not logged in then force to the profile page.
				$event->preventDefault();
				$event->stopPropagation();
				$event->result = false;
				global $ID;
				send_redirect(wl($ID,array('do'=>'login'),true,'&'));
				return;
			}
			if ($event->data != 'profile' && $USERINFO) {			
				//msg("Redirect to profile...");
				// If not logged in then force to the profile page.
				$event->preventDefault();
				$event->stopPropagation();
				$event->result = false;
				global $ID;
				send_redirect(wl($ID,array('do'=>'profile'),true,'&'));
				return;
			}
		}
		//msg(serialize(array($USERINFO, $event->data, $this->getConf("optinout"), $this->get_clearance())));
		return true;
	}

    /**
     * Sets a flag if we are working with the profile. This ensures that extra data is only updated when the profile is being worked on.
     */
    private function _verify_in_profile(&$event, $param) {
		// Check if this is the condition we are trying to monitor.
		$this->modifyProfile = $event->data == 'profile';
		return true;
	}

    /**
     * Logout this session from two factor authentication.  Purge any existing
     * OTP from the user's attributes.
     */
    private function _logout() {
		if ($this->attribute) {
			$this->attribute->del("twofactor","otp");
		}
		// Before we get here, the session is closed. Reopen it to logout the user.
		if (!headers_sent()) {
            session_start();
			//$_SESSION[DOKU_COOKIE]['twofactor_clearance'] = false;
			unset($_SESSION[DOKU_COOKIE]['twofactor_clearance']);
			session_write_close();
			//msg('_logout: '.serialize($_SESSION));
		}
		else {
			msg("Error! You have not been logged off!!!", -1);
		}
		//unset($_SESSION['twofactor_clearance']);
	}

    /**
     * See if the current session has passed two factor authentication.
     * @return bool - true if the session as successfully passed two factor
     *      authentication.
     */
    public function get_clearance() {
		//msg('get_clearance: '.serialize($_SESSION));
		return isset($_SESSION[DOKU_COOKIE]['twofactor_clearance']) && $_SESSION[DOKU_COOKIE]['twofactor_clearance'] === true;
		//return isset($_SESSION['twofactor_clearance'])  && $_SESSION['twofactor_clearance'] === true;
	}

    /**
     * Flags this session as having passed two factor authentication.
     * @return bool - returns true on successfully granting two factor clearance.
     */
    private function _grant_clearance() {
		//msg("Granting clearance.");
		// Purge the otp code as a security measure.
		$this->attribute->del("twofactor","otp");
		if (!headers_sent()) {
            session_start();
			$_SESSION[DOKU_COOKIE]['twofactor_clearance'] = true;			
			//msg('_grant_clearance: '.serialize($_SESSION));
			session_write_close();
		}
		else {
			msg("Error! You have not been logged in!!!", -1);
		}
		//return $_SESSION['twofactor_clearance']=true;
	}

    /**
     * If the conditions are right, process any updates to this module's attributes.
     */
    function twofactor_process_changes(&$event, $param) {
		// If the plugin is disabled, then exit.
		if ($this->getConf("enable") !== 1 || !$this->success) { return; }
		// If a password was required but incorrect, we would not be here.
		// The updateprofile method would have aborted earlier.
		// If this is a modify event, we are ok.
		if ($event->data['type'] == 'modify' && $this->modifyProfile) {
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
			// Process default module.
			$defaultmodule = $INPUT->str('default_module', '');
			if ($defaultmodule) {
				$useableMods = array();
				foreach($this->modules as $name=>$mod) {
					if(!$mod->canAuthLogin() && $mod->canUse()) { 
						$useableMods[$mod->getLang("name")] = $mod; 
					}
				}
				if (array_key_exists($defaultmodule, $useableMods)) {
					$this->attribute->set("twofactor", "defaultmod", $defaultmodule);
					$changed = true;
				}
			}
			// Update module settings.
			$sendotp = null;
			foreach ($this->modules as $name=>$mod){
				$result = $mod->processProfileForm();
				//msg("$name: ".serialize($result));
				// false:change failed  'failed':OTP failed  null: no change made
				$changed |= $result !== false && $result !== 'failed' && $result !== null;
				switch((string)$result) {
					case 'verified':
						// Remove used OTP.
						$this->attribute->del("twofactor","otp");
						msg($mod->getLang('passedsetup'), 1);
						// The OTP was valid.  Clear the login so the user can continue unbothered.
						$this->_grant_clearance();						
						break;
					case 'failed':
						msg($mod->getLang('failedsetup'), -1);
						break;
					case 'otp':
						if (!$sendotp) {
							$sendotp = $mod;							
						}						
				}
			}
			// Send OTP if requested.
			if ($sendotp) {
				// Force the message since it will fail the canUse function.				
				if ($this->_send_otp($sendotp, true)) {
					msg($sendotp->getLang('needsetup'), 1);
				}
				else {
					msg("Could not send message using ".get_class($sendotp),-1);
				}
			}

			// Update change status if changed.
			//msg(serialize($changed));
			if ($changed) {
				msg($this->getLang('updated'), 1);
				// If there are no functioning two factor options and two factor is mandatory, then revoke the login.				
				$available = false;
				foreach ($this->modules as $mod) {
					$available |= $mod->canUse();
				}
				//msg(serialize(array($this->getConf("optinout"), $available, $this->get_clearance())));
				if ($this->getConf("optinout") == 'mandatory' && !$available && $this->get_clearance()) {
					//msg("Force logging out");
					$this->_logout();
				}
				// TODO: get the profile page to return if any two factor changes are made.
				$event->preventDefault();
				$event->stopPropagation();
				$event->result = false;
				global $ID;
				send_redirect(wl($ID,array('do'=>'profile'),true,'&'));
			}
		}
		return ;
	}

    /**
     * Handles the authentication check. Screens Google Authenticator OTP, if available.
	 * NOTE: NOT LOGGED IN YET. Attribute requires user name.
     */
    function twofactor_before_auth_check(&$event, $param) {
		global $ACT, $INPUT;
		
		// If two factor is disabled, then there is nothing to do here.
		if ($this->getConf("enable") !== 1) return; 
		
		// Only operate if this is a login.
		//if ($ACT !== 'login') return;
		
		// If there is no supplied username, then there is nothing to check at this time.
		if (!$event->data['user']) { return; }
		
		$user = $_SERVER['REMOTE_USER'] != '' ? $_SERVER['REMOTE_USER'] : $event->data['user'];
		// If there is no active user name, then purge our two factor clearance token.
		if ($_SERVER['REMOTE_USER'] == '') {
			$this->_logout();
		}

		// If the user still has clearance, then we can skip this.		
		if ($this->get_clearance()) { return; }
		
		$workingMods = array();
		foreach($this->modules as $name=>$mod) {
			if($mod->canAuthLogin() && $mod->canUse($user)) { 
				$workingMods[] = $mod; 
			}
		}
		if (count($workingMods) > 0 && $user) {  
			$otp = $INPUT->str('otp','');
			if ($otp) {
				// Check for any modules that support OTP at login and are ready for use.
				foreach ($workingMods as $mod){
					$result = $mod->processLogin($otp, $user);
					//msg("Checking login with ".get_class($mod)." result:".serialize($result));
					if ($result) { 
						// The OTP code was valid.
						$this->_grant_clearance();
						return;					
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
				$useableMods = array();
				foreach($this->modules as $name=>$mod) {
					if(!$mod->canAuthLogin() && $mod->canUse($user)) { 
						$useableMods[] = $mod; 
					}
				}
				#$useableMods = array_filter($this->modules, function ($mod) { return !$mod->canAuthLogin(); });
				if (count($useableMods) == 0) {
					// There is no other two factor option, and this user did not supply a GA OTP code.
					// Revoke the logon.
					msg($this->getLang('mustusetoken'), -1);
					$event->preventDefault();
					return;
				}
			}					
		}
		
		// Check to see if the user has configured any module for use.
		$useableMods = array();
		foreach($this->modules as $name=>$mod) {
			if(!$mod->canAuthLogin() && $mod->canUse($user)) { 
				$useableMods[] = $mod; 
			}
		}
		if (count($useableMods) == 0) {
			// If the user has not configured either option and two factor is not mandatory, then grant clearance.				
			if ($this->getConf("optinout") != 'mandatory') {
				//There is no two factor configured for this user and it is not mandatory. Give clearance.
				//msg("Granting defacto login.");
				$this->_grant_clearance();
			}				
			if ($ACT == 'admin') { // If heading to the admin page, bypass. The user can't use two factor but is trying to admin the site.
				return;
			}
			// Otherwise this is mandatory.  Stop the default action, and set ACT to profile so the user can configure their two factor.
			//msg("twofactor_before_auth_check sending to profile.");
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
		$twofactor = $this->get_clearance();
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
			$useableMods = array();
			foreach($this->modules as $name=>$mod) {
				if(!$mod->canAuthLogin() && $mod->canUse()) { 
					$useableMods[$mod->getLang("name")] = $mod; 
				}
			}
			if (count($useableMods) == 0) {
				// If the user has not configured either option and two factor is not mandatory, then grant clearance.				
				if ($this->getConf("optinout") != 'mandatory') {
					//There is no two factor configured for this user and it is not mandatory. Give clearance.
					$this->_grant_clearance();
					return;
				}	
				if ($ACT == 'admin') { // If heading to the admin page, bypass. The user can't use two factor but is trying to admin the site.
					return;
				}
				if ($ACT != 'profile') {
					// Otherwise this is mandatory.  Stop the default action, and set ACT to profile so the user can configure their two factor.
					//msg("twofactor_after_auth_check sending to profile.");
					$ACT = 'profile';
				}
				return;
			}		
			
			// See if the user is quitting OTP.  We don't call it logoff because we don't want the user to think they are logged in!
			// This has to be checked before the template is started.
			if ($INPUT->has('otpquit')) {
				// Redirect to logoff.
				//$event->preventDefault();
				$event->stopPropagation();
				$ACT = 'logout';
				return;
			}

			// If a OTP has been submitted by the user, then verify the OTP.
			// If verified, then grant clearance and continue normally.
			$otp = $INPUT->str('otpcode');
			if ($otp && !$INPUT->has('resend')) {
				foreach ($useableMods as $mod){
					$result = $mod->processLogin($otp, $user);
					//msg("Checking login with ".get_class($mod)." result:".serialize($result));
					if ($result) { 
						// The OTP code was valid.
						$this->_grant_clearance();
						return;					
					}
				}
			}
			
			// Check if the user asked to generate and resend the OTP.
			if ($INPUT->has('resend')) {
				if	($INPUT->has('useall')) {
					$defaultMod = null;
				}
				else {
					$defaultMod = $this->attribute->exists("twofactor","defaultmod") ? $this->attribute->get("twofactor","defaultmod") : null;
				}
				// At this point, try to send the OTP.
				$this->_send_otp($defaultMod);
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
		$twofactor = $this->get_clearance();
		if ($_SERVER['REMOTE_USER'] == '' || $twofactor === true) { return; }
		
		// If the user is logging out, don't stop them.
		global $ACT;
		if ($ACT == 'logoff') { return; }
		
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
			$useableMods = array();
			foreach($this->modules as $name=>$mod) {
				if(!$mod->canAuthLogin() && $mod->canUse()) { 
					$useableMods[$mod->getLang("name")] = $mod; 
				}
			}
			$useableMods = array_filter($this->modules, function ($mod) { return $mod->canUse(); });
			if (count($useableMods) == 0 && $ACT == 'profile') {
				// We are heading to the profile page because nothing is setup.  Good.
				return;
			}
			
			if ($ACT == 'admin') { // In case we are heading to the admin page to fix something, bypass.
				return;
			}
			
			// Ensure the OTP exists and is still valid. If we need to, send a OTP.
			$otpQuery = $this->get_otp_code();
			if ($otpQuery == false) {
				$useableMods = array();
				foreach($this->modules as $name=>$mod) {
					if(!$mod->canAuthLogin() && $mod->canUse()) { 
						$useableMods[$mod->getLang("name")] = $mod; 
					}
				}
				$defaultMod = $this->attribute->exists("twofactor","defaultmod") ? $this->attribute->get("twofactor","defaultmod") : null;
				$mod = array_key_exists($defaultMod, $useableMods) ? $useableMods[$defaultMod] : null;
				$this->_send_otp($mod);
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
    private function _send_otp($module = null,$force = false) {
		if ($module === null) {			
			$module = array_filter($this->modules, function ($x){ return $x->canUse(); });
		}
		if (!is_array($module)) {			
			$module = array($module);
		}		
		if (count($module)==1) {
			$modname = get_class($module[0]);
		} 
		else {
			$modname = null;
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
				$success += $mod->transmitMessage($message, $force) ? 1 : 0;
			}
		}
		
		// If partially successful, store the OTP code and the timestamp the OTP expires at.		
		if ($success > 0) {			
			$otpData = array($otp, time() + $this->getConf('sentexpiry') * 60, $modname);
			if (!$this->attribute->set("twofactor","otp", $otpData)){
				msg("Unable to record OTP for later use.", -1);
			}
		}
		return $success == 0 ? false : ($success == count($mod) ? true : $success);
	}
	
	public function get_otp_code() {
		$otpQuery = $this->attribute->get("twofactor","otp", $success);		
		if (!$success) { return false; }
		list($otp, $expiry, $modname) = $otpQuery;
		if (time() > $expiry) {			
			$this->attribute->del("twofactor","otp");
			return false;
		}
		return array($otp, $modname);
	}
}
