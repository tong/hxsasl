package sasl;

/*
	[The PLAIN Simple Authentication and Security Layer (SASL) Mechanism](https://www.ietf.org/rfc/rfc4616.txt)

	The PLAIN mechanism should not be used without adequate data security protection as this mechanism affords no integrity or confidentiality protections itself.

	By default, implementations SHOULD advertise and make use of the PLAIN mechanism only when adequate data security services are in place.
*/
class PlainMechanism implements Mechanism {

	public final name = 'PLAIN';

	public function new() {}

	public function createAuthenticationText( authzid : String, authcid : String, password : String ) : String {
		
		if( authzid == null || authcid == null )
			return null;
		
		// //TODO authzid

		// var z = String.fromCharCode( 0 );
		// return '$z$authcid$z$password';
		
		//Buffer.from(`\0${params.user}\0${params.password}`);
		
		var b = new StringBuf();
		b.add( String.fromCharCode( 0 ) );
		b.add( authcid );
		b.add( String.fromCharCode( 0 ) );
		b.add( password );
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
