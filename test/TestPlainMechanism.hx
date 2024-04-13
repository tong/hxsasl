import utest.Assert.*;

class TestPlainMechanism extends utest.Test {
	function test_mechanism() {
		var mech = new sasl.PlainMechanism();
		equals('PLAIN', mech.name);
	}

	function test_createAuthenticationText() {
		var z = String.fromCharCode(0);
		var mech = new sasl.PlainMechanism();
		isNull(mech.createAuthenticationText(null, null, null));
		isNull(mech.createAuthenticationText(null, null, '1234'));
		isNull(mech.createAuthenticationText(null, 'user', '1234'));

		var t = mech.createAuthenticationText('example.com', null, '1234');
		equals(17, t.length);
		equals('example.com', t.substr(1, 11));
		equals('1234', t.substr(13, 4));
	}

	function test_createChallengeResponse() {
		var mech = new sasl.PlainMechanism();
		equals(null, mech.createChallengeResponse('challenge'));
	}
}
