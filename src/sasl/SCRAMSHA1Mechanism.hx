package sasl;

import haxe.crypto.Base64;
import haxe.crypto.Hmac;
import haxe.crypto.Sha1;
import haxe.io.Bytes;
import haxe.io.BytesBuffer;
import haxe.io.UInt8Array;

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
		cnonce = Std.string( haxe.crypto.Md5.encode( name + NAME ) ).substr( 0, 32 );//TODO
		initialMessage = 'n=' + saslname( username ) + ',r=' + cnonce;
		return GS2 + initialMessage;
	}

	public function createChallengeResponse( challenge : String ) : String {
		final serverMessage = Base64.decode( challenge ).toString();
		final ch = parseChallenge( serverMessage );
		final snonce = ch.r;
		if( !snonce.startsWith( cnonce ) )
			throw 'invalid snonce';
	    final salt = Base64.decode( ch.s );
		final iterations = ch.i;
		final clientFinalMessageBare = 'c=biws,r='+snonce;
		final saltedPassword = Hi( password, salt, iterations );
		final clientKey = HMAC( saltedPassword, Bytes.ofString( CLIENT_KEY ) );
		final serverKey = HMAC( saltedPassword, Bytes.ofString( SERVER_KEY ) );
		final storedKey = H( clientKey );
	    final authMessage = Bytes.ofString( initialMessage + ',' + serverMessage + ',' + clientFinalMessageBare );
		final clientSignature = HMAC( storedKey, authMessage );
		final serverSignature = HMAC( serverKey, authMessage );
	    final clientProof = XOR( clientKey, clientSignature );
		final response = clientFinalMessageBare + ',p=' + Base64.encode( clientProof );
		return response;
	}

	public function handleAuthenticationText( text : String ) : Array<String> {
		//TODO
		return null;
	}

	public static function parseChallenge( challenge : String ) : { r: String, s: String, i : Int } {
		//var str = decodeBase64( challenge ).toString();
		final res = { r: null, s: null, i: null };
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

	static inline function HMAC( key : Bytes, msg : Bytes ) : Bytes
		return new Hmac( SHA1 ).make( key, msg );

	static inline function H( msg : Bytes ) : Bytes
		return Sha1.make( msg );

	static function Hi( text : String, salt : Bytes, iterations : Int ) {
		final buf = new BytesBuffer();
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
		final res = new BytesBuffer();
		if( a.length > b.length )
			for( i in 0...b.length ) res.addByte( a.get(i) ^ b.get(i) );
		else
			for( i in 0...a.length ) res.addByte( a.get(i) ^ b.get(i) );
		return res.getBytes();
	}

	static function saslname( name : String ) : String {
		final escaped = new Array<String>();
		var cur = '';
		for( i in 0...name.length ) {
			switch cur = name.charAt( i ) {
			case ',': escaped.push( '=2C' );
			case '=': escaped.push( '=3D' );
			default: escaped.push( cur );
			}
		}
		return escaped.join( '' );
	}
}
