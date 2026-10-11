package sasl;

import haxe.crypto.Base64;
import haxe.crypto.Hmac;
import haxe.crypto.Hmac.HashMethod;
import haxe.crypto.Sha1;
import haxe.crypto.Sha256;
import haxe.io.Bytes;
import haxe.io.BytesBuffer;

using StringTools;

/**
	Salted Challenge Response Authentication Mechanism (SCRAM).

	Base class of the `SCRAM-*` mechanisms, parameterized by hash function.

	https://tools.ietf.org/html/rfc5802
**/
@rfc(5802)
abstract class SCRAMMechanism implements Mechanism {
	public static inline var CLIENT_KEY = 'Client Key';
	public static inline var SERVER_KEY = 'Server Key';
	public static inline var GS2 = 'n,,';

	static inline var BLOCK_SIZE = 64;

	public final name:String;

	/**
		Hash function of this mechanism.
	**/
	public final hash:HashMethod;

	final hashLength:Int;

	var username:String;
	// var host : String;
	var password:String;
	var cnonce:String;
	var initialMessage:String;
	var serverSignature:Bytes;
	var verified = false;

	/**
		@param name Mechanism name
		@param hash Hash function, `SHA1` or `SHA256`
		@param cnonce Client nonce; a fresh random nonce is generated per authentication if omitted (only set this for testing).
	**/
	function new(name:String, hash:HashMethod, ?cnonce:String) {
		this.name = name;
		this.hash = hash;
		this.hashLength = switch hash {
			case SHA1: 20;
			case SHA256: 32;
			case _: throw new Error('unsupported hash: $hash');
		}
		this.cnonce = cnonce;
	}

	/**
		`username` and `password` are prepared with SASLprep.

		Unassigned code points are allowed in both, also in the password which RFC 5802 treats as stored string,
		as otherwise passwords containing characters newer than Unicode 3.2 (like emoji) could not be used at all.

		@throws sasl.Error If `username` or `password` contains prohibited characters
	**/
	public function createAuthenticationText(username:String, host:String, password:String):String {
		this.username = StringPrep.prep(username, {allowUnassigned: true});
		this.password = StringPrep.prep(password, {allowUnassigned: true});
		if (this.username == null)
			throw new Error('invalid username');
		if (this.password == null)
			throw new Error('invalid password');
		if (cnonce == null || initialMessage != null)
			cnonce = Base64.encode(randomBytes(18));
		initialMessage = 'n=' + saslname(this.username) + ',r=' + cnonce;
		serverSignature = null;
		verified = false;
		return GS2 + initialMessage;
	}

	/**
		Creates the client-final message from the server-first message.

		Some servers send the server-final message as an additional challenge, which gets verified and answered with an empty response.

		@throws sasl.Error If the server reported an error or sent invalid data
	**/
	public function createChallengeResponse(challenge:String):String {
		final serverMessage = decodeBase64(challenge).toString();
		if (serverSignature != null) {
			if (!(verified = verifyServerFinal(serverMessage)))
				throw new Error('invalid server signature');
			return '';
		}
		if (initialMessage == null)
			throw new Error('authentication not started');
		final attrs = parseAttributes(serverMessage);
		if (attrs.exists('e'))
			throw new Error('server error: ' + attrs.get('e'));
		if (attrs.exists('m'))
			throw new Error('unsupported mandatory extension');
		final snonce = attrs.get('r');
		if (snonce == null || snonce.length <= cnonce.length || !snonce.startsWith(cnonce))
			throw new Error('invalid server nonce');
		final s = attrs.get('s');
		if (s == null || s.length == 0)
			throw new Error('missing salt');
		final salt = decodeBase64(s);
		final i = attrs.get('i');
		if (i == null || !~/^[1-9][0-9]{0,8}$/.match(i))
			throw new Error('invalid iteration count');
		final iterations = Std.parseInt(i);
		final clientFinalMessageBare = 'c=biws,r=' + snonce;
		final saltedPassword = Hi(password, salt, iterations);
		final clientKey = HMAC(saltedPassword, Bytes.ofString(CLIENT_KEY));
		final serverKey = HMAC(saltedPassword, Bytes.ofString(SERVER_KEY));
		final storedKey = H(clientKey);
		final authMessage = Bytes.ofString(initialMessage + ',' + serverMessage + ',' + clientFinalMessageBare);
		final clientSignature = HMAC(storedKey, authMessage);
		serverSignature = HMAC(serverKey, authMessage);
		final clientProof = XOR(clientKey, clientSignature);
		final response = clientFinalMessageBare + ',p=' + Base64.encode(clientProof);
		return response;
	}

	/**
		Verifies the server signature of the server-final message `v=…`.

		Returns `false` if the signature does not match, the server reported an error, or no server-final message was received at all.
	**/
	public function verifySuccess(data:String):Bool {
		if (data == null || data.length == 0 || data == '=')
			return verified; // Server-final message already received as challenge
		if (serverSignature == null)
			return false;
		return verified = try verifyServerFinal(decodeBase64(data).toString()) catch (e:Error) false;
	}

	public function handleAuthenticationText(text:String):Array<String> {
		// TODO
		return null;
	}

	public static function parseChallenge(challenge:String):{r:String, s:String, i:Null<Int>} {
		final attrs = parseAttributes(challenge);
		return {r: attrs.get('r'), s: attrs.get('s'), i: attrs.exists('i') ? Std.parseInt(attrs.get('i')) : null};
	}

	static function parseAttributes(message:String):Map<String, String> {
		final attrs = new Map<String, String>();
		for (e in message.split(',')) {
			final i = e.indexOf('=');
			if (i == -1)
				continue;
			final key = e.substr(0, i);
			if (!attrs.exists(key))
				attrs.set(key, e.substr(i + 1));
		}
		return attrs;
	}

	function verifyServerFinal(message:String):Bool {
		final attrs = parseAttributes(message);
		if (attrs.exists('e') || !attrs.exists('v'))
			return false;
		return equals(decodeBase64(attrs.get('v')), serverSignature);
	}

	/**
		Returns `length` random bytes from the platform's secure random source,
		falling back to `Std.random` (not secure) where none is available.
	**/
	static function randomBytes(length:Int):Bytes {
		#if nodejs
		return js.node.Crypto.randomBytes(length).hxToBytes();
		#elseif js
		final a = new js.lib.Uint8Array(length);
		js.Syntax.code("globalThis.crypto.getRandomValues({0})", a);
		return Bytes.ofData(a.buffer);
		#elseif sys
		if (sys.FileSystem.exists('/dev/urandom')) {
			final i = sys.io.File.read('/dev/urandom');
			final b = i.read(length);
			i.close();
			return b;
		}
		#end
		final b = Bytes.alloc(length);
		for (i in 0...length)
			b.set(i, Std.random(256));
		return b;
	}

	inline function HMAC(key:Bytes, msg:Bytes):Bytes
		return new Hmac(hash).make(key, msg);

	function H(msg:Bytes):Bytes
		return switch hash {
			case SHA256: Sha256.make(msg);
			case _: Sha1.make(msg);
		}

	/**
		PBKDF2 with HMAC as pseudorandom function and a single output block.

		HMAC is computed inline after U1 to avoid re-padding the key on every iteration:
		`HMAC(K, m) = H((K ^ opad) || H((K ^ ipad) || m))`
	**/
	function Hi(text:String, salt:Bytes, iterations:Int):Bytes {
		var key = Bytes.ofString(text);
		final buf = new BytesBuffer();
		buf.add(salt);
		for (b in [0, 0, 0, 1]) // INT(1)
			buf.addByte(b);
		var u = HMAC(key, buf.getBytes());
		final result = u.sub(0, hashLength);
		if (key.length > BLOCK_SIZE)
			key = H(key);
		final inner = Bytes.alloc(BLOCK_SIZE + hashLength);
		final outer = Bytes.alloc(BLOCK_SIZE + hashLength);
		for (i in 0...BLOCK_SIZE) {
			final k = (i < key.length) ? key.get(i) : 0;
			inner.set(i, k ^ 0x36);
			outer.set(i, k ^ 0x5c);
		}
		for (_ in 1...iterations) {
			inner.blit(BLOCK_SIZE, u, 0, hashLength);
			outer.blit(BLOCK_SIZE, H(inner), 0, hashLength);
			u = H(outer);
			for (j in 0...hashLength)
				result.set(j, result.get(j) ^ u.get(j));
		}
		return result;
	}

	static function decodeBase64(s:String):Bytes {
		return try Base64.decode(s) catch (e) throw new Error('invalid base64', e);
	}

	/**
		Constant time comparison.
	**/
	static function equals(a:Bytes, b:Bytes):Bool {
		if (a.length != b.length)
			return false;
		var d = 0;
		for (i in 0...a.length)
			d |= a.get(i) ^ b.get(i);
		return d == 0;
	}

	static function XOR(a:Bytes, b:Bytes):Bytes {
		final res = new BytesBuffer();
		if (a.length > b.length)
			for (i in 0...b.length)
				res.addByte(a.get(i) ^ b.get(i));
		else
			for (i in 0...a.length)
				res.addByte(a.get(i) ^ b.get(i));
		return res.getBytes();
	}

	static function saslname(name:String):String {
		final escaped = new Array<String>();
		var cur = '';
		for (i in 0...name.length) {
			switch cur = name.charAt(i) {
				case ',':
					escaped.push('=2C');
				case '=':
					escaped.push('=3D');
				default:
					escaped.push(cur);
			}
		}
		return escaped.join('');
	}
}
