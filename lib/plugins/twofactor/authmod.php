<?php
abstract class Twofactor_Auth_Module {
	protected $twofactor = null;
	protected $settings = null;
	
	/**
	 * As a requirement, this class and its subclasses require the attribute
	 * plugin for access to user data. An array will be passed in that the 
	 * calling class will handle saving data changes.  As such, the calling 
	 * class will ensure that the correct user's settings are presented to 
	 * this module.
	 */
	public function __construct(&$twofactor, &$settings){
		$this->twofactor = &$twofactor;
		$this->settings = &$settings;
	}
	
	/**
	 * This is called to see if the user can use it to login.
	 * @return bool - True if this module has access to all needed information 
	 * to perform a login.
	 */
    abstract public function canUse();
	
	/**
	 * This is called to see if the module provides login functionality on the 
	 * main login page.
	 * @return bool - True if this module provides main login functionality.
	 */
    abstract public function canAuthLogin();

	/**
	 * This is called to render the user configurable portion of the module 
	 * inside the user's profile.  Default is to render nothing.
	 * @return array - Array of HTML form elements to insert into the profile 
	 *     page.
	 */
    public function renderProfileForm() { return array(); }
    
	/**
	 * This is called to process the user configurable portion of the module 
	 * inside the user's profile.
	 * @return mixed - True if the user's settings were changed, false if 
	 *     settings could not be changed, null if no settings were changed, 
	 *     the string 'verified' if the module was successfully verified,
	 *     the string 'failed' if the module failed verification,
	 *	   the string 'otp' if the module is requesting a one-time password
	 *     for verification.
	 */
    public function processProfileForm() { return null; }    
    
	/**
	 * This is called to see if the module can send a message to the user.
	 * @return bool - True if a message can be sent to the user.
	 */
	abstract public function canTransmitMessage();

	/**
	 * This is called to relay a message to the user.  The message should 
	 * usually have a code for the user, but might be used to send a notice 
	 * that someone has logged in using their account.
	 * @return bool - True if the message was sucecssfully transmitted.
	 */
	public function transmitMessage($message) { return false; }

	/**
	 * This is called to validate the code provided.  The default is to see if 
	 * the code matches the one-time password.
	 * @return bool - True if the user has successfully authenticated using 
	 * this mechanism.
	 */
	public function processLogin($code) {
		$otpQuery = $this->twofactor->get_opt_code();
		if (!otpQuery) { return false; }
		list($otp, $destination) = $otpQuery;
		return ($code == $otp && $code != '' && ($destination == null || 'auth_module_' . $destination == get_called_class()));
	}
	
	/**
	 * This is a helper function to get text strings from the twofactor class 
	 * calling this module.	 
	 * @return string - Language string from the calling class.
	 */
	protected function getLang($key) {
		return $this->twofactor->getLang("twofactor_" . $key);
	}
	
	/**
	 * This is a helper function to get configuration from the twofactor class 
	 * calling this module.	 
	 * @return mixed - Configuration data from the calling class.
	 */
	protected function getConf($key) {
		return $this->twofactor->getConf($key);
	}
}