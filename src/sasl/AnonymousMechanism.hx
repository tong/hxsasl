package sasl;

/**
	[Anonymous Simple Authentication and Security Layer](https://tools.ietf.org/html/rfc4505) SASL Mechanism

	Unlike many other SASL mechanisms, whose purpose is to authenticate and identify the user to a server, the purpose of this SASL mechanism is to allow the user to gain access to services or resources without requiring the user to establish or otherwise disclose their identity to the server.  
	That is, this mechanism provides an anonymous login method.
	This mechanism does not provide a security layer.
**/
@rfc(4505)
class AnonymousMechanism implements Mechanism {
	public final name = "ANONYMOUS";

	/**
		Some servers may send a challenge to gather more information such as email address.
	**/
	public var challengeResponse:String;

	public function new(challengeResponse = "any") {
		this.challengeResponse = challengeResponse;
	}

	public function createAuthenticationText(user:String, host:String, pass:String):String {
		return null;
	}

	public function createChallengeResponse(challenge:String):String {
		return challengeResponse; // Not required
	}

	public function handleAuthenticationText(text:String):Array<String> {
		return null;
	}
}
