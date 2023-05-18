package sasl;

/**
	[The PLAIN Simple Authentication and Security Layer (SASL) Mechanism](https://www.ietf.org/rfc/rfc4616.txt)

	The PLAIN mechanism should not be used without adequate data security
    protection as this mechanism affords no integrity or confidentiality
    protections itself.

	By default, implementations SHOULD advertise and make use of the PLAIN
    mechanism only when adequate data security services are in place.
**/
@rfc(4616)
class PlainMechanism implements Mechanism {

	public final name = 'PLAIN';

    public var useAuthcid : Bool;

	public function new(useAuthcid = true) {
        this.useAuthcid = useAuthcid;
    }

	public function createAuthenticationText(authzid: String, authcid: String, password: String) : String {
		//TODO authzid
		//return '$z$authzid$z$password';
        if(authzid == null)
            return null;
        var b = new StringBuf();
		b.add(String.fromCharCode(0));
        b.add(authzid);
        if(useAuthcid && authcid != null) {
            b.add(String.fromCharCode(0));
		    b.add(authcid);
        }
		b.add(String.fromCharCode(0));
		b.add(password);
        return b.toString();
	}

	/**
		This mechanism will never get a challenge from the server.
	**/
	public function createChallengeResponse( challenge : String ) : String {
		return null;
	}

	public function handleAuthenticationText( text : String ) : Array<String> {
		if( text == null )
			return [];
		var a = text.split( String.fromCharCode( 0 ) );
		a.shift();
		return a;
	}

}
