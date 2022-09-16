
import utest.Assert.*;

class TestAnonymousMechanism extends utest.Test {

	var mech = new sasl.AnonymousMechanism();

	function test_createAuthenticationText() {
		equals( null, mech.createAuthenticationText( 'user', null, 'password' ) );
	}

    function test_createChallengeResponse() {
		equals( 'any', mech.createChallengeResponse( 'challenge' ) );
	}
}
