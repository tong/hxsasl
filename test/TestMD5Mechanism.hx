
import haxe.crypto.Base64;
import haxe.io.Bytes;
import sasl.MD5Mechanism;
import utest.Assert.*;

class TestMD5Mechanism extends utest.Test {

	var mech = new sasl.MD5Mechanism();

	function test_createAuthenticationText() {
		equals( null, mech.createAuthenticationText('user','host','password') );
	}

    function test_parseChallenge() {

		var challenge = 'cmVhbG09ImphYmJlci5kaXNrdHJlZS5uZXQiLG5vbmNlPSJZYUErQVMrSXdwbFRBUFgzZTU4NVVnVDZBMUJoL2dMVzhZWGpkWTY0IixjaGFyc2V0PXV0Zi04LGFsZ29yaXRobT1tZDUtc2Vzcw==';
		var r = MD5Mechanism.parseChallenge( challenge );

		equals( 'jabber.disktree.net', r.realm );
		equals( 'YaA+AS+IwplTAPX3e585UgT6A1Bh/gLW8YXjdY64', r.nonce );
	}

	@:access(sasl.MD5Mechanism)
	function test_computeResponse() {

		var host = 'jabber.disktree.net';
		var serverType = 'xmpp';
		var username = 'tong';
		var realm = 'jabber.disktree.net';
		var password = 'test';
		var nonce = 'YaA+AS+IwplTAPX3e585UgT6A1Bh/gLW8YXjdY64';
		var digest_uri = '$serverType/$host';
		var cnonce = 'YickYRKK8b';

		var X = '$username:$realm:$password';
		equals( 'tong:jabber.disktree.net:test', X );

		var Y = MD5Mechanism.H( Bytes.ofString( X ) );
		equals( '1cBjf9VjDQhvBL280dOySw==', Base64.encode(Y) );
		equals( 'd5c0637fd5630d086f04bdbcd1d3b24b', Y.toHex() );

		/*
		#if nodejs
		//var A1 = Y+':$nonce:$cnonce';
		var buf = new haxe.io.BytesBuffer();
		buf.add(Y);
		buf.addString(':$nonce:$cnonce');
		var A1 = buf.getBytes().toString();

		#else
		var A1 = Y+':$nonce:$cnonce';

		#end
		*/

		//TODO A1 is broken on all except cpp,neko
        //trace();
/*
		var A1 = Y+':$nonce:$cnonce';
		var A2 = 'AUTHENTICATE:${digest_uri}';

		equals( 'd5c0637fd5630d086f04bdbcd1d3b24b3a5961412b41532b4977706c54415058336535383555675436413142682f674c573859586a645936343a5969636b59524b4b3862', Bytes.ofString(A1).toHex() );
		equals( '41555448454e5449434154453a786d70702f6a61626265722e6469736b747265652e6e6574', Bytes.ofString(A2).toHex() );

		equals( 'AUTHENTICATE:xmpp/jabber.disktree.net', A2 );

		var HA1 = MD5Mechanism.HH( A1 );
		var HA2 = MD5Mechanism.HH( A2 );

		equals( '28303d327229d6aeb8f0c63df3842dae', HA1 );
		equals( '8baa447cbf2e204e03287d8bce2fc84f', HA2 );

		var KD = '$HA1:$nonce:00000001:$cnonce:auth:$HA2';
		var Z = MD5Mechanism.HH( KD );

		equals( '28303d327229d6aeb8f0c63df3842dae:YaA+AS+IwplTAPX3e585UgT6A1Bh/gLW8YXjdY64:00000001:YickYRKK8b:auth:8baa447cbf2e204e03287d8bce2fc84f', KD );
		equals( 'bef82e55d5636c6c18c142b58e686f91', Z );
*/
		/*
		//var byte = Bytes.alloc( Y.length + nonce.length + cnonce.length );
		var buf = new haxe.io.BytesBuffer();
		buf.add(Y);
		buf.add( Bytes.ofString(':'+nonce+':'+cnonce) );
		//buf.add( Bytes.ofString(':'+cnonce) );
		trace(buf.getBytes());
		var A1 = buf.getBytes();
		var A2 = 'AUTHENTICATE:${digest_uri}';

		//var A1 = Y+':$nonce:$cnonce';
		//var A2 = 'AUTHENTICATE:${digest_uri}';
		trace( A1 );
		trace( A2 );
		//equals( 'AUTHENTICATE:xmpp/jabber.disktree.net', Base64.encode(A1) );
		*/

		/*
		var HA1 = MD5Mechanism.HH( A1 );
		var HA2 = MD5Mechanism.HH( A2 );
		equals( '28303d327229d6aeb8f0c63df3842dae', HA1 );
		equals( '8baa447cbf2e204e03287d8bce2fc84f', HA2 );
		*/
	}


}
