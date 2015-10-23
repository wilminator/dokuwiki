<?php
// Load the Twofactor_Auth_Module Class
require_once(dirname(__FILE__).'/../twofactor/authmod.php');

class helper_plugin_twofactoraltemail extends Twofactor_Auth_Module {
	/** 
	 * If the user has a valid email address in their profile, then this can be used.
	 */
    public function canUse($user = null){
		global $USERINFO;		
		return ($this->attribute->exists("twofactoraltemail", "verified", $user) && $this->attribute->get("twofactoraltemail", "email", $success, $user) != $USERINFO['mail'] && $this->getConf('enable') === 1);
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
			$elements[] = form_makeTextField('altemail_email', $this->attribute->get("twofactoraltemail","email"), $this->getLang('email'), '' , 'block', array('size'=>'50', 'autocomplete'=>'off'));
			// If email has not been verified, then do so here.
			if (!$this->attribute->exists("twofactoraltemail", "verified")) {
				// Render the HTML to prompt for the verification/activation OTP.
				$elements[] = '<span>'.$this->getLang('verifynotice').'</span>';				
				$elements[] = form_makeTextField('altemail_verify', '', $this->getLang('verifymodule'), '', 'block', array('size'=>'50', 'autocomplete'=>'off'));
				$elements[] = form_makeCheckboxField('altemail_send', '1', $this->getLang('resendcode'),'','block');
			}			
			if ($this->attribute->exists("twofactoraltemail","email")) {
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
			// Delete the verified setting.
			$this->attribute->del("twofactoraltemail", "verified");
			return true;
		}
		$otp = $INPUT->str('altemail_verify', '');
		if ($otp) { // The user will use email.
			$checkResult = $this->processLogin($otp);
			// If the code works, then flag this account to use email.
			if ($checkResult == false) {
				return 'failed';
			}
			else {
				$this->attribute->set("twofactoraltemail", "verified", true);
				return 'verified';
			}					
		}							
		
		$changed = null;
		$email = $INPUT->str('altemail_email', '');
		if ($email != $this->attribute->get("twofactoraltemail","email")) {
			if ($this->attribute->set("twofactoraltemail","email", $email)== false) {
				msg("TwoFactor: Error setting alternate email.", -1);
			}
			// Delete the verification for the email if it was changed.
			$this->attribute->del("twofactoraltemail", "verified");
			$changed = true;
		}
		
		// If the data changed and we have everything needed to use this module, send an otp.
		if ($changed && $this->attribute->exists("twofactoraltemail", "email")) {
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
		$to = $this->attribute->get("twofactoraltemail", "email");
		// Create the email object.
		$mail = new Mailer();
		$subject = $conf['title'].' login verification';
		$mail->to($to);
		$mail->subject($subject);
		$mail->setText($message);			
		$result = $mail->send();
		// This is here only for debugging for me for now.  My windows box can't send out emails :P
		if (!result) { msg($message, 0); return true;}
		return $result;
		}
	
	/**
	 * 	This module uses the default authentication.
	 */
    //public function processLogin($code);
}