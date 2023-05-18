package sasl;

import haxe.crypto.Base64;
import haxe.crypto.Hmac;
import haxe.crypto.Sha1;
import haxe.io.Bytes;
import haxe.io.UInt8Array;
import haxe.io.BytesBuffer;

using StringTools;

/**
	Salted Challenge Response Authentication Mechanism (SCRAM).

	https://tools.ietf.org/html/rfc5802
**/
@rfc(5802)
class SCRAMSHA1Mechanism implements Mechanism {

	public static inline var NAME = 'SCRAM-SHA-1';

	public static inline var CLIENT_KEY = 'Client Key';
	public static inline var SERVER_KEY = 'Server Key';
	public static inline var GS2 = 'n,,';

	public final name = NAME;
	//public var clientFirst(default,null) = true;

	var username : String;
	//var host : String;
	var password : String;
	var cnonce : String;
	var initialMessage : String;

	public function new() {}

	public function createAuthenticationText( username : String, host : String, password : String ) : String {

		this.username = username;
		//this.host = host;
		this.password = password;

		cnonce = createRandomNonce( 32 ); //TODO
		initialMessage = 'n=' + saslname( username ) + ',r=' + cnonce;
		return GS2 + initialMessage;
	}

	public function createChallengeResponse( challenge : String ) : String {

		var serverMessage = decodeBase64( challenge ).toString();
		var ch = parseChallenge( serverMessage );

		var snonce = ch.r;
		if( !snonce.startsWith( cnonce ) )
			throw 'invalid snonce';
		var salt = decodeBase64( ch.s );
		var iterations = ch.i;

		var clientFinalMessageBare = 'c=biws,r='+snonce;
		var saltedPassword = Hi( password, salt, iterations );
		var clientKey = HMAC( saltedPassword, Bytes.ofString( CLIENT_KEY ) );
		var serverKey = HMAC( saltedPassword, Bytes.ofString( SERVER_KEY ) );
		var storedKey = H( clientKey );
		var authMessage = Bytes.ofString( initialMessage + ',' + serverMessage + ',' + clientFinalMessageBare );
		var clientSignature = HMAC( storedKey, authMessage );
		var serverSignature = HMAC( serverKey, authMessage );
		var clientProof = XOR( clientKey, clientSignature );
		var response = clientFinalMessageBare + ',p=' + encodeBase64( clientProof );

		return response;
	}

	public function handleAuthenticationText( text : String ) : Array<String> {
		//TODO
		return null;
	}

	public static function parseChallenge( challenge : String ) : { r: String, s: String, i : Int } {
		//var str = decodeBase64( challenge ).toString();
		var res = { r: null, s: null, i: null };
		var map = new Map<String,String>();
		for( e in challenge.split( "," ) ) {
			var parts = e.split( "=" );
			switch parts[0] {
			case 'r': res.r = parts[1];
			case 's': res.s = parts[1];
			case 'i': res.i = Std.parseInt( parts[1] );
			}
		}
		return res;
	}

	function createRandomNonce( length : Int ) : String {
		//TODO
		return Std.string( haxe.crypto.Md5.encode( name + NAME ) ).substr( 0, length );
	}

	static inline function HMAC( key : Bytes, msg : Bytes ) : Bytes {
		return new Hmac( SHA1 ).make( key, msg );
	}

	static inline function H( msg : Bytes ) : Bytes {
		return Sha1.make( msg );
	}

	static function Hi( text : String, salt : Bytes, iterations : Int ) {
		var buf = new BytesBuffer();
		buf.add( salt );
		buf.addByte( 0 );
		buf.addByte( 0 );
		buf.addByte( 0 );
		buf.addByte( 1 );
		var ui1 = HMAC( Bytes.ofString( text ), buf.getBytes() );
		var ui = ui1;
		for( i in 0...iterations - 1 ) {
			ui1 = HMAC( Bytes.ofString( text ), ui1 );
			ui = XOR( ui, ui1 );
		}
		return ui;
	}

	static function XOR( a : Bytes, b : Bytes ) : Bytes {
		var res = new BytesBuffer();
		if( a.length > b.length ) {
			for( i in 0...b.length ) res.addByte( a.get(i) ^ b.get(i) );
		} else {
			for( i in 0...a.length ) res.addByte( a.get(i) ^ b.get(i) );
		}
		return res.getBytes();
	}

	static inline function encodeBase64( buf : Bytes ) : String {
		return Base64.encode( buf );
	}

	static inline function decodeBase64( str : String ) : Bytes {
		return Base64.decode( str );
	}

	static function saslname( name : String ) : String {
		var escaped = new Array<String>();
		var curr = '';
		for( i in 0...name.length ) {
			curr = name.charAt( i );
			switch curr {
			case ',': escaped.push( '=2C' );
			case '=': escaped.push( '=3D' );
			default: escaped.push( curr );
			}
		}
		return escaped.join( '' );
	}
}
