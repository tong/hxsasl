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
		@param username Authentication identity (authcid)
		@param host Server host
		@param password Password
		@return Initial response or `null` if none
	**/
	function createAuthenticationText(username:String, host:String, password:String):String;

	/**
		@param challenge Base64 encoded server challenge
		@throws sasl.Error If the challenge is invalid or reports an error
	**/
	function createChallengeResponse(challenge:String):String;

	/**
		Verifies the additional data the server sent with its success outcome.

		Returns `false` if the server failed to prove its identity, in which case the client must not proceed.

		@param data Base64 encoded additional data, `null` or empty if none
	**/
	function verifySuccess(data:String):Bool;

	/**
	**/
	function handleAuthenticationText(text:String):Array<String>;
}
