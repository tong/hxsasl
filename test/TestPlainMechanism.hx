import utest.Assert.*;

class TestPlainMechanism extends utest.Test {
	static final NUL = String.fromCharCode(0);

	function test_mechanism() {
		var mech = new sasl.PlainMechanism();
		equals('PLAIN', mech.name);
	}

	// https://www.rfc-editor.org/rfc/rfc4616#section-4
	function test_createAuthenticationText() {
		var mech = new sasl.PlainMechanism();
		equals(NUL + 'tim' + NUL + 'tanstaaftanstaaf', mech.createAuthenticationText('tim', null, 'tanstaaftanstaaf'));
		equals(NUL + 'tim' + NUL + 'tanstaaftanstaaf', mech.createAuthenticationText('tim', 'example.com', 'tanstaaftanstaaf'));

		var mech = new sasl.PlainMechanism('Ursel');
		equals('Ursel' + NUL + 'Kurt' + NUL + 'xipj3plmq', mech.createAuthenticationText('Kurt', null, 'xipj3plmq'));
	}

	function test_createAuthenticationText_invalid() {
		var mech = new sasl.PlainMechanism();
		isNull(mech.createAuthenticationText(null, null, null));
		isNull(mech.createAuthenticationText(null, null, '1234'));
		isNull(mech.createAuthenticationText('user', null, null));
		isNull(mech.createAuthenticationText('', null, '1234'));
		isNull(mech.createAuthenticationText('user', null, ''));
		isNull(mech.createAuthenticationText('us' + NUL + 'er', null, '1234'));
		isNull(mech.createAuthenticationText('user', null, '12' + NUL + '34'));
		isNull(new sasl.PlainMechanism('a' + NUL).createAuthenticationText('user', null, '1234'));
	}

	function test_saslprep() {
		var mech = new sasl.PlainMechanism('\u2168');
		equals('\u2168' + NUL + 'IX' + NUL + 'a b', mech.createAuthenticationText('I\u00ADX', null, 'a\u00A0b'));
		equals(NUL + 'user' + NUL + 'pass\u{1F600}', new sasl.PlainMechanism().createAuthenticationText('user', null, 'pass\u{1F600}'));
		isNull(new sasl.PlainMechanism().createAuthenticationText('\u00AD', null, '1234'), 'empty after preparation');
		isNull(new sasl.PlainMechanism().createAuthenticationText('user', null, 'a\u0007b'), 'prohibited');
	}

	function test_createChallengeResponse() {
		var mech = new sasl.PlainMechanism();
		equals(null, mech.createChallengeResponse('challenge'));
	}

	function test_handleAuthenticationText() {
		var mech = new sasl.PlainMechanism();
		same(['', 'tim', 'tanstaaftanstaaf'], mech.handleAuthenticationText(NUL + 'tim' + NUL + 'tanstaaftanstaaf'));
		same(['Ursel', 'Kurt', 'xipj3plmq'], mech.handleAuthenticationText('Ursel' + NUL + 'Kurt' + NUL + 'xipj3plmq'));
		isNull(mech.handleAuthenticationText(null));
		isNull(mech.handleAuthenticationText('tim' + NUL + 'pw'));
		isNull(mech.handleAuthenticationText(NUL + NUL + 'pw'));
		isNull(mech.handleAuthenticationText(NUL + 'tim' + NUL));
		isNull(mech.handleAuthenticationText(NUL + 'a' + NUL + 'b' + NUL + 'c'));
	}
}
