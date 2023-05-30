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

	public final name = 'PLAIN';

    public var useAuthcid : Bool;

	public function new(useAuthcid = true) {
        this.useAuthcid = useAuthcid;
    }

    /**
        @param authzid Authorization identity
        @param authcid Authentication identity
        @param password Password
    **/
	public function createAuthenticationText(authzid: String, authcid: String, password: String) : String {
        if(authzid == null)
            return null;
        //TODO: string prep
        // final authcid_p = StrinPrep.prep(authcid, true);
        // final password_p = StrinPrep.prep(password, true);
        // if(authcid_p == null || password_p == null 
        //     || authcid_p.length==0 || password_p.length==0)
        //     return null;
        final buf = new StringBuf();
		buf.add(String.fromCharCode(0));
        buf.add(authzid);
        if(useAuthcid && authcid != null) {
            buf.add(String.fromCharCode(0));
		    buf.add(authcid);
        }
		buf.add(String.fromCharCode(0));
		buf.add(password);
        return buf.toString();
	}

	/**
		This mechanism will never get a challenge from the server.
	**/
	public function createChallengeResponse(challenge: String) : String {
		return null;
	}

	public function handleAuthenticationText(text: String) : Array<String> {
		if( text == null )
			return [];
        final a = text.split(String.fromCharCode(0));
		a.shift();
		return a;
	}

}
