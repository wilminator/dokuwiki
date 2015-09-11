<?php
// Load the PHPGangsta_GoogleAuthenticator Class
require_once(dirname(__FILE__).'../GoogleAuthenticator.php');
// Load the PHP QR Code library.
require_once(dirname(__FILE__).'../phpqrcode.php');

/**
 * If we turn this into a helper class, it can have its own language and settings files.
 * Until then, we can only use per-user settings.
 */
class auth_module_googleauth extends Twofactor_Auth_Module {
	/** 
	 * The user must have verified their GA is configured correctly first.
	 */
    public function canUse(){		
		return (array_key_exists("verified", $this->settings));
	}
	
	/**
	 * This module does provide authentication functionality at the main login screen.
	 */
    public function canAuthLogin() {
		return true;
	}
		
	/**
	 * This user will need to interact with the QR code in order to configure GA.
	 */
    public function renderProfileForm(){
		$elements = array();
		$ga = new PHPGangsta_GoogleAuthenticator();			
		if (array_key_exists("secret", $this->settings)) { // The user has a revokable GA secret.
			// Show the QR code so the user can add other devices.
			$mysecret = $this->settings["secret"];
			$data = $this->twofactor_generateQRCodeData($USERINFO['mail'], $mysecret);			
			$elements[] = '<figure><figcaption>'.$this->getLang('scanwithga').'</figcaption>';
			$elements[] = '<img src="'.$data.'" alt="'.$this->getLang('twofactor_scanwithga').'" />';
			$elements[] = '</figure>';
			// Check to see if the user needs to verify the code.
			if (!array_key_exists("verified", $this->settings)){
				$elements[] = '<span>'.$this->getLang('twofactor_verifyga').'</span>';
				$twofa_form = form_makeTextField('googleauth_verify', '', $this->getLang('twofactor_verifymodule'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
				$elements[] = $twofa_form;
			}
			// Show the option to revoke the GA secret.
			$twofa_form = form_makeCheckboxField('googleauth_disable', '1', $this->getLang('killmodule'), '', 'block');
			$elements[] = $twofa_form;
		}
		else { // The user may opt in using GA.
			//Provide a checkbox to create a personal secret.
			$twofa_form = form_makeCheckboxField('googleauth_enable', '1', $this->getLang('enablemodule'), '', 'block');
			$elements[] = $twofa_form;
		}
		return $elements;
	}

	/**
	 * Process any user configuration.
	 */	
    public function processProfileForm(){
		$ga = new PHPGangsta_GoogleAuthenticator();
		$hasSecret = array_key_exists('secret', $this->settings);
		$oldmysecret = $hasSecret ? $this->settings["secret"] : null;
		if ($hasSecret) {
			if ($INPUT->bool('googleauth_disable', false)) {
				unset $this->settings["secret"];
				// Also delete the seenqrcode attribute.  Otherwise the system will still expect the user to login with GA.
				$this->settings["verified"];
				return true;
			}
			else {
				$otp = $INPUT->str('googleauth_verify', '');
				if ($otp) { // The user will use GA.
					$checkResult = $this->processLogin($otp);
					// If the code works, then flag this account to use GA.
					if ($checkResult == false) {
						return 'failed';
					}
					else {
						$this->settings['verified'] = true;
						return 'verified';
					}					
				}
			}
		}
		else {
			if ($INPUT->bool('googleauth_enable', false) && !$hasSecret) { // Only make a code if one is not set.
				$mysecret = $ga->createSecret();
				$this->setting['secret'] = $mysecret;
				return true;
			}
		}
		return null;
	}	
	
	/**
	 * This module cannot send messages.
	 */
	//public function canTransmitMessage();
	
	/**
	 * Transmit the message via email to the address on file.
	 * As a special case, configure the mail settings to send only via text.
	 */
	//public function transmitMessage($message);
	
	/**
	 * 	This module authenticates against a time-based code.
	 */
    public function processLogin($code){ 
		$ga = new PHPGangsta_GoogleAuthenticator();
		$expiry = $this->getConf("codeexpiry");
		$secret = $this->settings['secret'];
		return $ga->verifyCode($this->settings['secret'], $code, $expiry);
	}
}