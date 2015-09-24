<?php
class auth_module_smsappliance extends Twofactor_Auth_Module {
	/** 
	 * If the user has a valid email address in their profile, then this can be used.
	 */
    public function canUse(){		
		return (array_key_exists("verified", $this->settings));
	}
	
	/**
	 * This module can not provide authentication functionality at the main login screen.
	 */
    public function canAuthLogin() {
		return false;
	}
		
	/**
	 * This user will need to supply a phone number and their cell provider.
	 */
    public function renderProfileForm(){
		$elements = array();
			// Provide an input for the phone number.			
			$phone = array_key_exists('phone', $this->settings) ? $this->settings['phone'] : '';
			$elements['phone'] = form_makeTextField('phone', $phone, $this->getLang('phone'), '', 'block', array('size'=>'50'));
			$providers = array_keys($this->smsappliance_getProviders());
			$provider = array_key_exists('provider', $this->settings) ? $this->settings['provider'] : $providers[0];
			$twofa_form = form_makeListboxField('smsappliance_provider', $providers, $provider, $this->getLang('provider'), '', 'block');
			$elements[] = $twofa_form;

			// If the phone number has not been verified, then do so here.
			if ($phone) {
				if (!array_key_exists('verified', $this->settings)) {
					// Render the HTML to prompt for the verification/activation OTP.
					$elements[] = '<span>'.$this->getLang('verifynotice').'</span>';				
					$elements[] = form_makeTextField('smsappliance_verify', '', $this->getLang('verify'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
					$elements[] = form_makeCheckboxField('smsappliance_send', '1', $this->getLang('resend'),'','block');
				}
				// Render the element to remove the phone since it exists.
				$elements[] = form_makeCheckboxField('smsappliance_disable', '1', $this->getLang('disable'), '', 'block');
			}			
		return $elements;
	}

	/**
	 * Process any user configuration.
	 */	
    public function processProfileForm(){
		if ($INPUT->bool('smsappliance_disable', false)) {
			unset $this->settings["phone"];
			unset $this->settings["provider"];
			// Also delete the verified setting.  Otherwise the system will still expect the user to login with OTP.
			unset $this->settings["verified"];
			return true;
		}
		if (!$this->canUse()) {
			if ($INPUT->bool('smsappliance_send', false)) {
				return 'otp';
			}
			$otp = $INPUT->str('smsappliance_verify', '');
			if ($otp) { // The user will use SMS.
				$checkResult = $this->processLogin($otp);
				// If the code works, then flag this account to use SMS Gateway.
				if ($checkResult == false) {
					return 'failed';
				}
				else {
					$this->settings['verified'] = true;
					return 'verified';
				}					
			}							
		}
		
		$changed = null;
		$oldphone = array_key_exists('phone', $this->settings) ? $this->settings['phone'] : '';
		$phone = $INPUT->str('smsappliance_phone', '');
		if ($phone != $oldphone) {
			if ($this->attribute->set("twofactor","phone", $phone)== false) {
				msg("TwoFactor: Error setting phone.", -1);
			}
			// Delete the verification for the phone number if it was changed.
			unset $this->settings['verified'];
			$changed = true;
		}
		
		return $changed;
	}	
	
	/**
	 * This module can send messages.
	 */
	public function canTransmitMessage(){
		return true;
	}
	
	/**
	 * Transmit the message via email to the address on file.
	 * As a special case, configure the mail settings to send only via text.
	 */
	public function transmitMessage($message){
		if (!$this->canUse()) { return false; }
		$number = $this->attribute->get("twofactor","phone", $success);
		if (!$success) {
			// If there is no phone number, then fail.
			return false;
		}
		$url = str_replace('$phone', $number, $this->getConf('otpurl'));
		$url = str_replace('$msg', rawurlencode($message), $url);
		// Deliver the message and capture the results.
		$result = file_get_contents($url);
		// TODO: How do we verify success?
		}
	
	/**
	 * 	This module uses the default authentication.
	 */
    //public function processLogin($code);
}