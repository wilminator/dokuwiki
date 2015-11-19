<?php
// Load the Twofactor_Auth_Module Class
require_once(dirname(__FILE__).'/../twofactor/authmod.php');

class helper_plugin_twofactoraltemail extends Twofactor_Auth_Module {
	/** 
	 * If the user has a valid email address in their profile, then this can be used.
	 */
    public function canUse($user = null){
		global $USERINFO;		
		return ($this->_settingExists("verified", $user) && $this->_settingGet("email", '', $user) != $USERINFO['mail'] && $this->getConf('enable') === 1);
	}
	
	/**
	 * This module can not provide authentication functionality at the main login screen.
	 */
    public function canAuthLogin() {
		return false;
	}
		
	/**
	 * This user will need to verify their email.
	 */
    public function renderProfileForm(){
		$elements = array();
			// Prompt for an email address.
			$email = $this->_settingGet("email");
			$elements[] = form_makeTextField('altemail_email', $email, $this->getLang('email'), '' , 'block', array('size'=>'50', 'autocomplete'=>'off'));
			// If email has not been verified, then do so here.
			if (!$this->_settingExists("verified") && $email) {
				// Render the HTML to prompt for the verification/activation OTP.
				$elements[] = '<span>'.$this->getLang('verifynotice').'</span>';				
				$elements[] = form_makeTextField('altemail_verify', '', $this->getLang('verifymodule'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
				$elements[] = form_makeCheckboxField('altemail_send', '1', $this->getLang('resendcode'),'','block');
			}			
			if ($this->_settingExists("email")) {
				// Render the element to remove email.
				$elements[] = form_makeCheckboxField('altemail_disable', '1', $this->getLang('killmodule'), '', 'block');
			}
		return $elements;
	}

	/**
	 * Process any user configuration.
	 */	
    public function processProfileForm(){
		global $INPUT, $USERINFO;
		if ($INPUT->bool('altemail_disable', false)) {
			// Delete the email address.
			$this->_settingDelete("email");
			// Delete the verified setting.
			$this->_settingDelete("verified");
			return true;
		}
		$oldemail = $this->_settingGet("email", '');
		if ($oldemail) {
			if ($INPUT->bool('altemail_send', false)) {
				return 'otp';
			}		
			$otp = $INPUT->str('altemail_verify', '');
			if ($otp) { // The user will use email.
				$checkResult = $this->processLogin($otp);
				// If the code works, then flag this account to use email.
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
		$email = $INPUT->str('altemail_email', '');
		if ($email != $oldemail) {
			if ($email == $USERINFO['mail']) {
				msg($this->getLang('notsameemail'),-1);
			}
			else {
				if ($this->_settingSet("email", $email)== false) {
					msg("TwoFactor: Error setting alternate email.", -1);
				}
				// Delete the verification for the email if it was changed.
				$this->_settingDelete("verified");
				$changed = true;
			}
		}
		
		// If the data changed and we have everything needed to use this module, send an otp.
		if ($changed && $this->_settingExists("email")) {
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
	 * As a special case, configure the mail settings to send only via text.
	 */
	public function transmitMessage($message, $force = false){		
		if (!$this->canUse()  && !$force) { return false; }
		$to = $this->_settingGet("email");
		// Create the email object.
		$mail = new Mailer();
		$subject = $conf['title'].' login verification';
		$mail->to($to);
		$mail->subject($subject);
		$mail->setText($message);			
		$result = $mail->send();
		return $result;
		}
	
	/**
	 * 	This module uses the default authentication.
	 */
    //public function processLogin($code);
}