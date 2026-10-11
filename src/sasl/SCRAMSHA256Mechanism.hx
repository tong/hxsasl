package sasl;

/**
	[SCRAM-SHA-256 SASL Mechanism](https://tools.ietf.org/html/rfc7677)
**/
@rfc(7677)
class SCRAMSHA256Mechanism extends SCRAMMechanism {
	public static inline var NAME = 'SCRAM-SHA-256';

	/**
		@param cnonce Client nonce; a fresh random nonce is generated per authentication if omitted (only set this for testing).
	**/
	public function new(?cnonce:String) {
		super(NAME, SHA256, cnonce);
	}
}
