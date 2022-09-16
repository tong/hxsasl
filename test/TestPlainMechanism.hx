
import utest.Assert.*;

class TestPlainMechanism extends utest.Test {
	
	function test_mechanism() {
		var mech = new sasl.PlainMechanism();
		equals( 'PLAIN', mech.name );
	}

	function test_createAuthenticationText() {
		var mech = new sasl.PlainMechanism();
		var z = String.fromCharCode( 0 );
		isNull( mech.createAuthenticationText( null, null, null ) );
		isNull( mech.createAuthenticationText( null, null, '1234' ) );
		isNull( mech.createAuthenticationText( null, 'user', '1234' ) );
		isNull( mech.createAuthenticationText( 'example.com', null, '1234' ) );
		equals( z+'user'+z+'1234', mech.createAuthenticationText( 'example.com', 'user', '1234' ) );
	}
	
    function test_createChallengeResponse() {
		var mech = new sasl.PlainMechanism();
		equals( null, mech.createChallengeResponse( 'challenge' ) );
	}
}
