import haxe.crypto.Base64;
import haxe.crypto.Hmac;
import haxe.crypto.Hmac.HashMethod;
import haxe.io.Bytes;
import sasl.SCRAMMechanism;
import sasl.SCRAMSHA1Mechanism;
import sasl.SCRAMSHA256Mechanism;
import utest.Assert.*;

class TestSCRAMSHA256Mechanism extends utest.Test {
	static inline function b64(s:String):String
		return Base64.encode(Bytes.ofString(s));

	function test_mechanism() {
		final m = new SCRAMSHA256Mechanism();
		equals('SCRAM-SHA-256', m.name);
		equals(SHA256, m.hash);
	}

	// https://www.rfc-editor.org/rfc/rfc7677#section-3
	function test_rfc7677() {
		final m = new SCRAMSHA256Mechanism('rOprNGfwEbeRWgbNEkqO');
		equals('n,,n=user,r=rOprNGfwEbeRWgbNEkqO', m.createAuthenticationText('user', null, 'pencil'));
		final serverFirst = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
		equals("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
			m.createChallengeResponse(b64(serverFirst)));
		isTrue(m.verifySuccess(b64('v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=')));
	}

	function test_wrongServerSignature() {
		final m = new SCRAMSHA256Mechanism('rOprNGfwEbeRWgbNEkqO');
		m.createAuthenticationText('user', null, 'pencil');
		m.createChallengeResponse(b64("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"));
		// SCRAM-SHA-1 signature length
		isFalse(m.verifySuccess(b64('v=rmF9pqV8S7suAoZWja4dJRkFsKQ=')));
	}

	// https://www.rfc-editor.org/rfc/rfc6070#section-2
	@:access(sasl.SCRAMMechanism)
	function test_Hi_rfc6070() {
		final m = new SCRAMSHA1Mechanism();
		equals('0c60c80f961f0e71f3a9b524af6012062fe037a6', m.Hi('password', Bytes.ofString('salt'), 1).toHex());
		equals('ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957', m.Hi('password', Bytes.ofString('salt'), 2).toHex());
		equals('4b007901b765489abead49d926f721d065a429c1', m.Hi('password', Bytes.ofString('salt'), 4096).toHex());
	}

	@:access(sasl.SCRAMMechanism)
	function test_Hi_reference() {
		final salt = Bytes.ofString('NaCl');
		for (m in ([new SCRAMSHA1Mechanism(), new SCRAMSHA256Mechanism()] : Array<SCRAMMechanism>)) {
			for (len in [0, 1, 63, 64, 65, 100]) {
				final password = [for (i in 0...len) String.fromCharCode(97 + i % 26)].join('');
				for (iterations in [1, 2, 3, 17]) {
					equals(referenceHi(m.hash, password, salt, iterations).toHex(), m.Hi(password, salt, iterations).toHex(),
						'${m.name} password length $len, $iterations iterations');
				}
			}
		}
	}

	static function referenceHi(hash:HashMethod, password:String, salt:Bytes, iterations:Int):Bytes {
		final hmac = new Hmac(hash);
		final key = Bytes.ofString(password);
		final msg = Bytes.alloc(salt.length + 4);
		msg.blit(0, salt, 0, salt.length);
		msg.set(salt.length + 3, 1);
		var u = hmac.make(key, msg);
		final result = u.sub(0, u.length);
		for (_ in 1...iterations) {
			u = hmac.make(key, u);
			for (j in 0...u.length)
				result.set(j, result.get(j) ^ u.get(j));
		}
		return result;
	}
}
