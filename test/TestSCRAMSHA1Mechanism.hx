
import utest.Assert.*;
import haxe.io.Bytes;
import sasl.SCRAMSHA1Mechanism;

class TestSCRAMSHA1Mechanism extends utest.Test {

	var mech = new SCRAMSHA1Mechanism();

	@:access(sasl.SCRAMSHA1Mechanism)
	function test_createAuthenticationText() {
		equals( 'n,,n=user,r=f63fa22e4accf72ab91b2b59af83c545', mech.createAuthenticationText( 'user', null, 'password' ) );
		equals( 'f63fa22e4accf72ab91b2b59af83c545', mech.cnonce );
		equals( 'n=user,r=f63fa22e4accf72ab91b2b59af83c545', mech.initialMessage );
	}

    function test_parseChallenge() {
		var c = SCRAMSHA1Mechanism.parseChallenge( 'r=0efd61802e130ed7ad814e8d6e014b7ec06c328d-29ca-4530-adc7-2644abad33df,s=5jZ9/GexSS3fDp4/PQTcSL01kZRURa3H,i=4096' );
		equals( '0efd61802e130ed7ad814e8d6e014b7ec06c328d-29ca-4530-adc7-2644abad33df', c.r );
		equals( '5jZ9/GexSS3fDp4/PQTcSL01kZRURa3H', c.s );
		equals( 4096, c.i );
	}

	@:access(sasl.SCRAMSHA1Mechanism)
	function test_createChallengeResponse() {

		var password = 'test';

		var initialMessage = 'n=user,r=f63fa22e4accf72ab91b2b59af83c545';
		var serverMessage = SCRAMSHA1Mechanism.decodeBase64( 'cj1mNjNmYTIyZTRhY2NmNzJhYjkxYjJiNTlhZjgzYzU0NTQ3ZTg0N2Q2LWUzOTgtNDA5ZC05OGRlLWZhNjI1MmU2ZjI5ZixzPTVqWjkvR2V4U1MzZkRwNC9QUVRjU0wwMWtaUlVSYTNILGk9NDA5Ng==' ).toString();
		var ch = SCRAMSHA1Mechanism.parseChallenge( serverMessage );
		var snonce = ch.r;
		var clientFinalMessageBare = 'c=biws,r='+snonce;

		var salt = SCRAMSHA1Mechanism.decodeBase64( ch.s );
		var iterations = ch.i;

		var saltedPassword = SCRAMSHA1Mechanism.Hi( password, salt, iterations );
		//trace( SCRAMSHA1Mechanism.encodeBase64( saltedPassword ) );
		equals( '5reb7rJoBLb3oMtpz1kMpurP9yY=', SCRAMSHA1Mechanism.encodeBase64( saltedPassword ) );

		/*
		#if nodejs
		var clientKey = SCRAMSHA1Mechanism.HMAC( saltedPassword, js.node.Buffer.from( SCRAMSHA1Mechanism.CLIENT_KEY ) );
		equals( 'NLHNGsBTkyQdh6SGwtHvBG6/OM8=', SCRAMSHA1Mechanism.encodeBase64( clientKey ) );
		var serverKey = SCRAMSHA1Mechanism.HMAC( saltedPassword, js.node.Buffer.from( SCRAMSHA1Mechanism.SERVER_KEY ) );
		equals( 'ZqjUswSIo0h+5epn1kAtKWu2JHc=', SCRAMSHA1Mechanism.encodeBase64( serverKey ) );

		#else
		var clientKey = SCRAMSHA1Mechanism.HMAC( saltedPassword, Bytes.ofString( SCRAMSHA1Mechanism.CLIENT_KEY ) );
		equals( 'NLHNGsBTkyQdh6SGwtHvBG6/OM8=', SCRAMSHA1Mechanism.encodeBase64( clientKey ) );
		var serverKey = SCRAMSHA1Mechanism.HMAC( saltedPassword, Bytes.ofString( SCRAMSHA1Mechanism.SERVER_KEY ) );
		equals( 'ZqjUswSIo0h+5epn1kAtKWu2JHc=', SCRAMSHA1Mechanism.encodeBase64( serverKey ) );

		#end

		var storedKey = SCRAMSHA1Mechanism.H( clientKey );
		equals( 'Retzkjz3oXdobOx5KDxWV8VZDTc=', SCRAMSHA1Mechanism.encodeBase64( storedKey ) );

		var authMessage = initialMessage + ',' + serverMessage + ',' + clientFinalMessageBare;

		#if nodejs
		var clientSignature = SCRAMSHA1Mechanism.HMAC( storedKey, js.node.Buffer.from( authMessage ) );
		#else
		var clientSignature = SCRAMSHA1Mechanism.HMAC( storedKey, Bytes.ofString( authMessage ) );
		#end
		*/

		var clientKey = SCRAMSHA1Mechanism.HMAC( saltedPassword, Bytes.ofString( SCRAMSHA1Mechanism.CLIENT_KEY ) );
		equals( 'NLHNGsBTkyQdh6SGwtHvBG6/OM8=', SCRAMSHA1Mechanism.encodeBase64( clientKey ) );
		var serverKey = SCRAMSHA1Mechanism.HMAC( saltedPassword, Bytes.ofString( SCRAMSHA1Mechanism.SERVER_KEY ) );
		equals( 'ZqjUswSIo0h+5epn1kAtKWu2JHc=', SCRAMSHA1Mechanism.encodeBase64( serverKey ) );

		var storedKey = SCRAMSHA1Mechanism.H( clientKey );
		equals( 'Retzkjz3oXdobOx5KDxWV8VZDTc=', SCRAMSHA1Mechanism.encodeBase64( storedKey ) );

		var authMessage = initialMessage + ',' + serverMessage + ',' + clientFinalMessageBare;
		var clientSignature = SCRAMSHA1Mechanism.HMAC( storedKey, Bytes.ofString( authMessage ) );

		equals( 'yyjZ0d2iVQ4MSKL6GRcJS5SA1Wg=', SCRAMSHA1Mechanism.encodeBase64( clientSignature ) );

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
		var h = SCRAMSHA1Mechanism.encodeBase64( SCRAMSHA1Mechanism.H( buffer ) );
		equals( 'qZk+NkcGgWq6PiVxeFDCbJzQ2J0=', h );

		var buffer = js.node.Buffer.from('abc');
		var h = SCRAMSHA1Mechanism.HMAC( buffer, 'xyz' );
		equals( 'joSS/6IA6pfEcKUwpc1UswfMJ2E=', h.toString('base64') );

		#else

		var bytes = Bytes.ofString('abc');
		var h = SCRAMSHA1Mechanism.encodeBase64( SCRAMSHA1Mechanism.H( bytes ) );
		equals( 'qZk+NkcGgWq6PiVxeFDCbJzQ2J0=', h );

		//var buffer = Bytes.ofString('abc');
		//var h = SCRAMSHA1Mechanism.HMAC( buffer, 'xyz' );
		//equals( 'joSS/6IA6pfEcKUwpc1UswfMJ2E=', SCRAMSHA1Mechanism.encodeBase64(h) );

		#end
	}
	*/

}
