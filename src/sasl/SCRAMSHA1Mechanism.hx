package sasl;

/**
	[SCRAM-SHA-1 SASL Mechanism](https://tools.ietf.org/html/rfc5802)
**/
@rfc(5802)
class SCRAMSHA1Mechanism extends SCRAMMechanism {
	public static inline var NAME = 'SCRAM-SHA-1';

	/**
		@param cnonce Client nonce; a fresh random nonce is generated per authentication if omitted (only set this for testing).
	**/
	public function new(?cnonce:String) {
		super(NAME, SHA1, cnonce);
	}
}
