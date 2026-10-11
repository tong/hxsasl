import utest.Assert.*;
import haxe.crypto.Base64;
import haxe.io.Bytes;
import sasl.SCRAMSHA1Mechanism;

class TestSCRAMSHA1Mechanism extends utest.Test {
	var mech = new SCRAMSHA1Mechanism('f63fa22e4accf72ab91b2b59af83c545');

	@:access(sasl.SCRAMSHA1Mechanism)
	function test_createAuthenticationText() {
		equals('n,,n=user,r=f63fa22e4accf72ab91b2b59af83c545', mech.createAuthenticationText('user', null, 'password'));
		equals('f63fa22e4accf72ab91b2b59af83c545', mech.cnonce);
		equals('n=user,r=f63fa22e4accf72ab91b2b59af83c545', mech.initialMessage);
	}

	@:access(sasl.SCRAMSHA1Mechanism)
	function test_randomNonce() {
		final a = new SCRAMSHA1Mechanism();
		a.createAuthenticationText('user', null, 'password');
		final first = a.cnonce;
		a.createAuthenticationText('user', null, 'password');
		final b = new SCRAMSHA1Mechanism();
		b.createAuthenticationText('user', null, 'password');
		equals(24, first.length);
		equals(-1, first.indexOf(','));
		notEquals(first, a.cnonce);
		notEquals(first, b.cnonce);
		notEquals(a.cnonce, b.cnonce);
	}

	// https://www.rfc-editor.org/rfc/rfc5802#section-5
	function test_rfc5802() {
		final m = new SCRAMSHA1Mechanism('fyko+d2lbbFgONRv9qkxdawL');
		equals('n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL', m.createAuthenticationText('user', null, 'pencil'));
		final challenge = Base64.encode(Bytes.ofString('r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096'));
		equals('c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=', m.createChallengeResponse(challenge));
	}

	static final RFC_CNONCE = 'fyko+d2lbbFgONRv9qkxdawL';
	static final RFC_SERVER_FIRST = 'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096';
	static final RFC_SERVER_FINAL = 'v=rmF9pqV8S7suAoZWja4dJRkFsKQ=';

	static inline function b64(s:String):String
		return Base64.encode(Bytes.ofString(s));

	static function rfcMech():SCRAMSHA1Mechanism {
		final m = new SCRAMSHA1Mechanism(RFC_CNONCE);
		m.createAuthenticationText('user', null, 'pencil');
		return m;
	}

	function test_verifySuccess() {
		var m = rfcMech();
		isFalse(m.verifySuccess(b64(RFC_SERVER_FINAL)), 'no server-first yet');
		m.createChallengeResponse(b64(RFC_SERVER_FIRST));
		isTrue(m.verifySuccess(b64(RFC_SERVER_FINAL)));

		m = rfcMech();
		m.createChallengeResponse(b64(RFC_SERVER_FIRST));
		isFalse(m.verifySuccess(b64('v=AAAAAAAAAAAAAAAAAAAAAAAAAAA=')));

		m = rfcMech();
		m.createChallengeResponse(b64(RFC_SERVER_FIRST));
		isFalse(m.verifySuccess(b64('e=invalid-proof')));

		m = rfcMech();
		m.createChallengeResponse(b64(RFC_SERVER_FIRST));
		isFalse(m.verifySuccess(null), 'missing server-final');
		isFalse(m.verifySuccess(''), 'missing server-final');
		isFalse(m.verifySuccess('='), 'missing server-final');
	}

	function test_serverFinalAsChallenge() {
		var m = rfcMech();
		m.createChallengeResponse(b64(RFC_SERVER_FIRST));
		equals('', m.createChallengeResponse(b64(RFC_SERVER_FINAL)));
		isTrue(m.verifySuccess(null));
		isTrue(m.verifySuccess(''));

		m = rfcMech();
		m.createChallengeResponse(b64(RFC_SERVER_FIRST));
		raises(() -> m.createChallengeResponse(b64('v=AAAAAAAAAAAAAAAAAAAAAAAAAAA=')), sasl.Error);
		isFalse(m.verifySuccess(null));
	}

	function test_invalidServerFirst() {
		for (msg in [
			'e=other-error',
			'm=ext,r=fyko+d2lbbFgONRv9qkxdawL3rfc,s=QSXCR+Q6sek8bf92,i=4096',
			's=QSXCR+Q6sek8bf92,i=4096',
			'r=xxxx+d2lbbFgONRv9qkxdawL3rfc,s=QSXCR+Q6sek8bf92,i=4096',
			'r=fyko+d2lbbFgONRv9qkxdawL,s=QSXCR+Q6sek8bf92,i=4096',
			'r=fyko+d2lbbFgONRv9qkxdawL3rfc,i=4096',
			'r=fyko+d2lbbFgONRv9qkxdawL3rfc,s=,i=4096',
			'r=fyko+d2lbbFgONRv9qkxdawL3rfc,s=QSXCR+Q6sek8bf92',
			'r=fyko+d2lbbFgONRv9qkxdawL3rfc,s=QSXCR+Q6sek8bf92,i=0',
			'r=fyko+d2lbbFgONRv9qkxdawL3rfc,s=QSXCR+Q6sek8bf92,i=-1',
			'r=fyko+d2lbbFgONRv9qkxdawL3rfc,s=QSXCR+Q6sek8bf92,i=4096x',
			'r=fyko+d2lbbFgONRv9qkxdawL3rfc,s=QSXCR+Q6sek8bf92,i=9999999999',
		]) {
			final m = rfcMech();
			raises(() -> m.createChallengeResponse(b64(msg)), sasl.Error, msg);
		}
		raises(() -> new SCRAMSHA1Mechanism().createChallengeResponse(b64(RFC_SERVER_FIRST)), sasl.Error, 'not started');
	}

	function test_parseChallenge() {
		var c = SCRAMSHA1Mechanism.parseChallenge('r=0efd61802e130ed7ad814e8d6e014b7ec06c328d-29ca-4530-adc7-2644abad33df,s=5jZ9/GexSS3fDp4/PQTcSL01kZRURa3H,i=4096');
		equals('0efd61802e130ed7ad814e8d6e014b7ec06c328d-29ca-4530-adc7-2644abad33df', c.r);
		equals('5jZ9/GexSS3fDp4/PQTcSL01kZRURa3H', c.s);
		equals(4096, c.i);
		final c = SCRAMSHA1Mechanism.parseChallenge('r=abc=def,s=QSXCR+Q6sek8bf92==,i=4096');
		equals('abc=def', c.r);
		equals('QSXCR+Q6sek8bf92==', c.s);
	}

	@:access(sasl.SCRAMSHA1Mechanism)
	function test_createChallengeResponse() {
		var password = 'test';

		var initialMessage = 'n=user,r=f63fa22e4accf72ab91b2b59af83c545';
		var serverMessage = Base64.decode('cj1mNjNmYTIyZTRhY2NmNzJhYjkxYjJiNTlhZjgzYzU0NTQ3ZTg0N2Q2LWUzOTgtNDA5ZC05OGRlLWZhNjI1MmU2ZjI5ZixzPTVqWjkvR2V4U1MzZkRwNC9QUVRjU0wwMWtaUlVSYTNILGk9NDA5Ng==')
			.toString();
		var ch = SCRAMSHA1Mechanism.parseChallenge(serverMessage);
		var snonce = ch.r;
		var clientFinalMessageBare = 'c=biws,r=' + snonce;

		var salt = Base64.decode(ch.s);
		var iterations = ch.i;

		var saltedPassword = SCRAMSHA1Mechanism.Hi(password, salt, iterations);
		// trace( Base64.encode( saltedPassword ) );
		equals('5reb7rJoBLb3oMtpz1kMpurP9yY=', Base64.encode(saltedPassword));

		/*
			#if nodejs
			var clientKey = SCRAMSHA1Mechanism.HMAC( saltedPassword, js.node.Buffer.from( SCRAMSHA1Mechanism.CLIENT_KEY ) );
			equals( 'NLHNGsBTkyQdh6SGwtHvBG6/OM8=', Base64.encode( clientKey ) );
			var serverKey = SCRAMSHA1Mechanism.HMAC( saltedPassword, js.node.Buffer.from( SCRAMSHA1Mechanism.SERVER_KEY ) );
			equals( 'ZqjUswSIo0h+5epn1kAtKWu2JHc=', Base64.encode( serverKey ) );

			#else
			var clientKey = SCRAMSHA1Mechanism.HMAC( saltedPassword, Bytes.ofString( SCRAMSHA1Mechanism.CLIENT_KEY ) );
			equals( 'NLHNGsBTkyQdh6SGwtHvBG6/OM8=', Base64.encode( clientKey ) );
			var serverKey = SCRAMSHA1Mechanism.HMAC( saltedPassword, Bytes.ofString( SCRAMSHA1Mechanism.SERVER_KEY ) );
			equals( 'ZqjUswSIo0h+5epn1kAtKWu2JHc=', Base64.encode( serverKey ) );

			#end

			var storedKey = SCRAMSHA1Mechanism.H( clientKey );
			equals( 'Retzkjz3oXdobOx5KDxWV8VZDTc=', Base64.encode( storedKey ) );

			var authMessage = initialMessage + ',' + serverMessage + ',' + clientFinalMessageBare;

			#if nodejs
			var clientSignature = SCRAMSHA1Mechanism.HMAC( storedKey, js.node.Buffer.from( authMessage ) );
			#else
			var clientSignature = SCRAMSHA1Mechanism.HMAC( storedKey, Bytes.ofString( authMessage ) );
			#end
		 */

		var clientKey = SCRAMSHA1Mechanism.HMAC(saltedPassword, Bytes.ofString(SCRAMSHA1Mechanism.CLIENT_KEY));
		equals('NLHNGsBTkyQdh6SGwtHvBG6/OM8=', Base64.encode(clientKey));
		var serverKey = SCRAMSHA1Mechanism.HMAC(saltedPassword, Bytes.ofString(SCRAMSHA1Mechanism.SERVER_KEY));
		equals('ZqjUswSIo0h+5epn1kAtKWu2JHc=', Base64.encode(serverKey));

		var storedKey = SCRAMSHA1Mechanism.H(clientKey);
		equals('Retzkjz3oXdobOx5KDxWV8VZDTc=', Base64.encode(storedKey));

		var authMessage = initialMessage + ',' + serverMessage + ',' + clientFinalMessageBare;
		var clientSignature = SCRAMSHA1Mechanism.HMAC(storedKey, Bytes.ofString(authMessage));

		equals('yyjZ0d2iVQ4MSKL6GRcJS5SA1Wg=', Base64.encode(clientSignature));

		/*
			var time = Sys.time();
			var key = Bytes.ofString('abcdefg123');
			var msg = Bytes.ofString('disktree');
			for( i in 0...10000 ) {
				var x = SCRAMSHA1Mechanism.HMAC( key, msg );
			}
			trace(Sys.time()-time);
		 */
	}
	/*
		@:access(sasl.SCRAMSHA1Mechanism)
		function test_crypto() {

			#if nodejs

			var buffer = js.node.Buffer.from('abc');
			var h = Base64.encode( SCRAMSHA1Mechanism.H( buffer ) );
			equals( 'qZk+NkcGgWq6PiVxeFDCbJzQ2J0=', h );

			var buffer = js.node.Buffer.from('abc');
			var h = SCRAMSHA1Mechanism.HMAC( buffer, 'xyz' );
			equals( 'joSS/6IA6pfEcKUwpc1UswfMJ2E=', h.toString('base64') );

			#else

			var bytes = Bytes.ofString('abc');
			var h = Base64.encode( SCRAMSHA1Mechanism.H( bytes ) );
			equals( 'qZk+NkcGgWq6PiVxeFDCbJzQ2J0=', h );

			//var buffer = Bytes.ofString('abc');
			//var h = SCRAMSHA1Mechanism.HMAC( buffer, 'xyz' );
			//equals( 'joSS/6IA6pfEcKUwpc1UswfMJ2E=', Base64.encode(h) );

			#end
		}
	 */
}
// TODO:
// https://wiki.xmpp.org/web/SASL_Authentication_and_SCRAM
/*
	Test vectors
	Here is a complete example:

	Username: user

	Password: pencil

	Client generates the random nonce fyko+d2lbbFgONRv9qkxdawL

	Initial message: n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL

	Server generates the random nonce 3rfcNHYJY1ZVvWVs7j

	Server replies: r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096

	The salt (hex): 4125c247e43ab1e93c6dff76

	Client final message bare: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j

	Salted password (hex): 1d96ee3a529b5a5f9e47c01f229a2cb8a6e15f7d

	Client key (hex): e234c47bf6c36696dd6d852b99aaa2ba26555728

	Stored key (hex): e9d94660c39d65c38fbad91c358f14da0eef2bd6

	Auth message: n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j

	Client signature (hex): 5d7138c486b0bfabdf49e3e2da8bd6e5c79db613

	Client proof (hex): bf45fcbf7073d93d022466c94321745fe1c8e13b

	Server key (hex): 0fe09258b3ac852ba502cc62ba903eaacdbf7d31

	Server signature (hex): ae617da6a57c4bbb2e0286568dae1d251905b0a4

	Client final message: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=

	Server final message: v=rmF9pqV8S7suAoZWja4dJRkFsKQ=

	Server's server signature (hex): ae617da6a57c4bbb2e0286568dae1d251905b0a4

	}
 */
