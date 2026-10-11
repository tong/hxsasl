package sasl;

/**
	[The PLAIN Simple Authentication and Security Layer (SASL) Mechanism](https://www.ietf.org/rfc/rfc4616.txt)

	The `PLAIN` mechanism should not be used without adequate data security
	protection as this mechanism affords no integrity or confidentiality
	protections itself.

	By default, implementations **SHOULD** advertise and make use of the `PLAIN`
	mechanism only when adequate data security services are in place.
**/
@rfc(4616)
class PlainMechanism implements Mechanism {
	static final NUL = String.fromCharCode(0);

	public final name = 'PLAIN';

	/**
		Authorization identity to act as; omitted from the message if `null` or empty.
	**/
	public var authzid:String;

	/**
		@param authzid Authorization identity, only needed to act as a different identity than the authenticated one
	**/
	public function new(?authzid:String) {
		this.authzid = authzid;
	}

	/**
		Creates the message `[authzid] NUL authcid NUL passwd`.

		`username` and `password` are prepared with SASLprep, `authzid` is sent as is.

		Returns `null` if `username` or `password` is empty or invalid, or `authzid` contains a `NUL` character.

		@param username Authentication identity (authcid)
		@param host Unused
		@param password Password
	**/
	public function createAuthenticationText(username:String, host:String, password:String):String {
		final authcid = StringPrep.prep(username, {allowUnassigned: true});
		final passwd = StringPrep.prep(password, {allowUnassigned: true});
		if (!isValid(authcid) || !isValid(passwd) || (authzid != null && authzid.indexOf(NUL) != -1))
			return null;
		return (authzid ?? '') + NUL + authcid + NUL + passwd;
	}

	/**
		This mechanism will never get a challenge from the server.
	**/
	public function createChallengeResponse(challenge:String):String {
		return null;
	}

	/**
		This mechanism provides no server authentication.
	**/
	public function verifySuccess(data:String):Bool {
		return true;
	}

	/**
		Parses a PLAIN message into `[authzid, authcid, password]`, with `authzid` being an empty string if absent.

		Returns `null` if the message is malformed.
	**/
	public function handleAuthenticationText(text:String):Array<String> {
		if (text == null)
			return null;
		final a = text.split(NUL);
		return (a.length == 3 && a[1].length > 0 && a[2].length > 0) ? a : null;
	}

	static inline function isValid(s:String):Bool
		return s != null && s.length > 0 && s.indexOf(NUL) == -1;
}
