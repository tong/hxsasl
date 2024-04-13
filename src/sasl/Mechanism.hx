package sasl;

/**
	Simple Authentication and Security Layer (SASL).

	https://www.rfc-editor.org/rfc/rfc4422
**/
interface Mechanism {
	/**
		The name associated with this mechanism
	**/
	final name:String;

	/**
	**/
	// var clientFirst(default,null) : Bool;

	/**
	 */
	function createAuthenticationText(authzid:String, authcid:String, password:String):String;

	/**
	**/
	function createChallengeResponse(challenge:String):String;

	/**
	**/
	function handleAuthenticationText(text:String):Array<String>;
}
