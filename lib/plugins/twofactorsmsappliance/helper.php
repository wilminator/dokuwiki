<?php
class helper_plugin_twofactorsmsappliance extends Twofactor_Auth_Module {
	/** 
	 * If the user has a valid email address in their profile, then this can be used.
	 */
    public function canUse($user = null){		
		return ($this->_settingExists("verified", $user));
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
			$phone = $this->_settingGet("phone", '');
			$elements[] = form_makeTextField('smsappliance_phone', $phone, $this->getLang('phone'), '', 'block', array('size'=>'50'));			

			// If the phone number has not been verified, then do so here.
			if ($phone) {
				if (!$this->_settingExists("verified")) {
					// Render the HTML to prompt for the verification/activation OTP.
					$elements[] = '<span>'.$this->getLang('verifynotice').'</span>';				
					$elements[] = form_makeTextField('smsappliance_verify', '', $this->getLang('verifymodule'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
					$elements[] = form_makeCheckboxField('smsappliance_send', '1', $this->getLang('resendcode'),'','block');
				}
				// Render the element to remove the phone since it exists.
				$elements[] = form_makeCheckboxField('smsappliance_disable', '1', $this->getLang('killmodule'), '', 'block');
			}			
		return $elements;
	}

	/**
	 * Process any user configuration.
	 */	
    public function processProfileForm(){
		global $INPUT;
		$phone = $INPUT->str('smsappliance_phone', '');
		//msg($phone);
		if ($INPUT->bool('smsappliance_disable', false) || $phone === '') {
			// Delete the phone number.
			$this->_settingDelete("phone");
			// Delete the verified setting.  Otherwise the system will still expect the user to login with OTP.
			$this->_settingDelete("verified");
			return true;
		}
		$oldphone = $this->_settingGet("phone", '');
		if ($oldphone) {
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
					$this->_settingSet("verified", true);
					return 'verified';
				}					
			}							
		}
		
		$changed = null;				
		if (preg_match('/^[0-9]{5,}$/',$phone) != false) { 
			if ($phone != $oldphone) {
				if ($this->_settingSet("phone", $phone)== false) {
					msg("TwoFactor: Error setting phone.", -1);
				}
				// Delete the verification for the phone number if it was changed.
				$this->_settingDelete("verified");
				return 'deleted';
			}
		}
		
		// If the data changed and we have everything needed to use this module, send an otp.
		if ($changed === true && $this->_settingExists("phone")) {
			$changed = 'otp';
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
	 */
	public function transmitMessage($message, $force = false){		
		if (!$this->canUse()  && !$force) { return false; }
		$number = $this->_settingGet("phone", null);
		if (!$number) {
			// If there is no phone number, then fail.
			return false;
		}
		$url = str_replace('$phone', $number, $this->getConf('url'));
		$url = str_replace('$msg', rawurlencode($message), $url);
		// Deliver the message and capture the results.
		$result = file_get_contents($url);
		// TODO: How do we verify success?
		return true;
		}
	
	/**
	 * 	This module uses the default authentication.
	 */
    //public function processLogin($code);
}