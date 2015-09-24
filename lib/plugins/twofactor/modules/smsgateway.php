<?php
class auth_module_smsgateway extends Twofactor_Auth_Module {
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
			$providers = array_keys($this->getProviders());
			$provider = array_key_exists('provider', $this->settings) ? $this->settings['provider'] : $providers[0];
			$twofa_form = form_makeListboxField('smsgateway_provider', $providers, $provider, $this->getLang('provider'), '', 'block');
			$elements[] = $twofa_form;

			// If the phone number has not been verified, then do so here.
			if ($phone) {
				if (!array_key_exists('verified', $this->settings)) {
					// Render the HTML to prompt for the verification/activation OTP.
					$elements[] = '<span>'.$this->getLang('verifynotice').'</span>';				
					$elements[] = form_makeTextField('smsgateway_verify', '', $this->getLang('verify'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
					$elements[] = form_makeCheckboxField('smsgateway_send', '1', $this->getLang('resend'),'','block');
				}
				// Render the element to remove the phone since it exists.
				$elements[] = form_makeCheckboxField('smsgateway_disable', '1', $this->getLang('disable'), '', 'block');
			}			
		return $elements;
	}

	/**
	 * Process any user configuration.
	 */	
    public function processProfileForm(){
		if ($INPUT->bool('smsgateway_disable', false)) {
			unset $this->settings["phone"];
			unset $this->settings["provider"];
			// Also delete the verified setting.  Otherwise the system will still expect the user to login with OTP.
			unset $this->settings["verified"];
			return true;
		}
		if (!$this->canUse()) {
			if ($INPUT->bool('smsgateway_send', false)) {
				return 'otp';
			}
			$otp = $INPUT->str('smsgateway_verify', '');
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
		$phone = $INPUT->str('smsgateway_phone', '');
		if ($phone != $oldphone) {
			if ($this->attribute->set("twofactor","phone", $phone)== false) {
				msg("TwoFactor: Error setting phone.", -1);
			}
			// Delete the verification for the phone number if it was changed.
			unset $this->settings['verified'];
			$changed = true;
		}
		
		$oldprovider = $this->attribute->get("twofactor","provider", $success);
		$provider = $INPUT->str('smsgateway_provider', '');
		if ($this->getConf("otpmethod") == 'smsgateway' && $this->attribute->exists("twofactor","phone") &&$provider != $oldprovider) {
			if ($this->attribute->set("twofactor","provider", $provider)== false) {
				msg("TwoFactor: Error setting provider.", -1);
			}
			// Delete the verification for the phone number if the carrier was changed.
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
		global $USERINFO, $conf;
		// Disable HTML for text messages.				
		$conf['htmlmail'] = 0;			
		$number = $this->settings["phone"];
		if (!$number) {
			msg("TwoFactor: User has not defined a phone number.  Failing.", -1);
			// If there is no phone number, then fail.
			return false;
		}
		$gateway = $this->settings["provider"];
		$providers = $this->getProviders();
		if (array_key_exists($gateway, $providers)) {
			$to = "{$number}@{$providers[$gateway]}";
		}
		else {
			$to = '';
		}
		if (!$to) {
			msg("TwoFactor: Unable to define To field for email.  Failing.", -1);
			// If there is no recipient address, then fail.
			return false;
		}
		// Create the email object.
		$mail = new Mailer();
		$subject = $conf['title'].' login verification';
		$mail->to($to);
		$mail->subject($subject);
		$mail->setText($message);			
		$result = $mail->send();
		// This is here only for debugging for me for now.  My windows box can't send out emails :P
		msg($message, 0);
		return $result;
		}
	
	/**
	 * 	This module uses the default authentication.
	 */
    //public function processLogin($code);

	
    /**
     * Produce an array of SMS gateway email domains with the keys as the
     * cellular providers.  Reads the gateway.txt file to generate the list.
     * @return array - keys are providers, values are the email domains used
     *      to email an SMS to a phone user.
     */
    private function getProviders() {
		$filename = dirname(__FILE__).'/../gateway.txt';
		$providers = array();
		$contents = explode("\n", io_readFile($filename));		
		foreach($contents as $line) {
			if (strstr($line, '@')) {
				list($provider, $domain) = explode("@", trim($line), 2);
				$providers[$provider] = $domain;
			}
		}
		return $providers;
	}
}