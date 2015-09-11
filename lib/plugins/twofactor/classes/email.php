<?php
class auth_module_email extends Twofactor_Auth_Module {
	/** 
	 * If the user has a valid email address in their profile, then this can be used.
	 */
    public function canUse(){
		global $USERINFO;
		return preg_match(".+@.+\..+", $USERINFO['mail']);
	}
	
	/**
	 * This module can not provide authentication functionality at the main login screen.
	 */
    public function canAuthLogin() {
		return false;
	}
		
	/**
	 * This module does not need any user configuration.
	 */
    //public function renderProfileForm();
    //public function processProfileForm();	
	
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
		global $USERINFO;
		$to = $USERINFO['mail'];
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
}