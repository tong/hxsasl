package sasl;

/**
	[SASLprep: Stringprep Profile for User Names and Passwords](https://datatracker.ietf.org/doc/html/rfc4013)

	Prepares Unicode strings representing user names and passwords for comparison,
	using the Unicode 3.2 tables of [stringprep](https://datatracker.ietf.org/doc/html/rfc3454).
**/
@rfc(4013)
class StringPrep {
	static inline var S_BASE = 0xAC00;
	static inline var L_BASE = 0x1100;
	static inline var V_BASE = 0x1161;
	static inline var T_BASE = 0x11A7;
	static inline var L_COUNT = 19;
	static inline var V_COUNT = 21;
	static inline var T_COUNT = 28;
	static inline var N_COUNT = V_COUNT * T_COUNT;
	static inline var S_COUNT = L_COUNT * N_COUNT;

	// Varint digits, see tools/gen-stringprep-data.py
	static inline var TERMINAL = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
	static inline var MORE = "abcdefghijklmnopqrstuvwxyz()*+-.";

	static var UNASSIGNED:Array<Int>;
	static var MAPPED_TO_NOTHING:Array<Int>;
	static var NON_ASCII_SPACE:Array<Int>;
	static var PROHIBITED:Array<Int>;
	static var RAND_AL_CAT:Array<Int>;
	static var L_CAT:Array<Int>;
	static var decompositions:Map<Int, Array<Int>>;
	static var compositions:Map<Int, Map<Int, Int>>;
	static var combiningClasses:Map<Int, Int>;

	/**
		Applies the SASLprep profile to `input`.

		Returns `null` if the result contains prohibited characters or fails the bidirectional check.

		@param options `allowUnassigned`: Allow code points unassigned in Unicode 3.2, as for queries (default `false`, as for stored strings)
	**/
	public static function prep(input:String, ?options:{allowUnassigned:Bool}):Null<String> {
		if (input == null)
			return null;
		final allowUnassigned = options != null && options.allowUnassigned;
		if (PROHIBITED == null)
			init();
		// 1. Map
		final mapped = new Array<Int>();
		for (c in new haxe.iterators.StringIteratorUnicode(input)) {
			if (inRanges(c, NON_ASCII_SPACE))
				mapped.push(0x20);
			else if (!inRanges(c, MAPPED_TO_NOTHING))
				mapped.push(c);
		}
		// 2. Normalize
		final cps = nfkc(mapped);
		// 3. Prohibit
		var hasRandAL = false, hasL = false;
		for (c in cps) {
			if (inRanges(c, PROHIBITED) || (!allowUnassigned && inRanges(c, UNASSIGNED)))
				return null;
			if (inRanges(c, RAND_AL_CAT))
				hasRandAL = true;
			else if (inRanges(c, L_CAT))
				hasL = true;
		}
		// 4. Check bidi
		if (hasRandAL && (hasL || !inRanges(cps[0], RAND_AL_CAT) || !inRanges(cps[cps.length - 1], RAND_AL_CAT)))
			return null;
		final buf = new StringBuf();
		for (c in cps)
			buf.addChar(c);
		return buf.toString();
	}

	/**
		Unicode normalization form KC.
	**/
	static function nfkc(cps:Array<Int>):Array<Int> {
		final d = new Array<Int>();
		for (c in cps)
			decompose(c, d);
		reorder(d);
		return compose(d);
	}

	static function decompose(c:Int, out:Array<Int>) {
		final s = c - S_BASE;
		if (s >= 0 && s < S_COUNT) {
			out.push(L_BASE + Std.int(s / N_COUNT));
			out.push(V_BASE + Std.int((s % N_COUNT) / T_COUNT));
			final t = s % T_COUNT;
			if (t != 0)
				out.push(T_BASE + t);
			return;
		}
		final d = decompositions.get(c);
		if (d == null)
			out.push(c);
		else
			for (x in d)
				out.push(x);
	}

	/**
		Canonical ordering: stable sort of each run of non-starters by combining class.
	**/
	static function reorder(cps:Array<Int>) {
		for (i in 1...cps.length) {
			final c = cps[i];
			final cc = combiningClass(c);
			if (cc == 0)
				continue;
			var j = i;
			while (j > 0 && combiningClass(cps[j - 1]) > cc) {
				cps[j] = cps[j - 1];
				j--;
			}
			cps[j] = c;
		}
	}

	static function compose(cps:Array<Int>):Array<Int> {
		if (cps.length == 0)
			return cps;
		final out = [cps[0]];
		var starterPos = 0;
		var lastClass = combiningClass(cps[0]);
		if (lastClass != 0)
			lastClass = 256; // Leading non-starter blocks composition
		for (i in 1...cps.length) {
			final c = cps[i];
			final cc = combiningClass(c);
			final composite = composePair(out[starterPos], c);
			if (composite != -1 && (lastClass < cc || lastClass == 0)) {
				out[starterPos] = composite;
				continue;
			}
			if (cc == 0)
				starterPos = out.length;
			lastClass = cc;
			out.push(c);
		}
		return out;
	}

	static function composePair(a:Int, b:Int):Int {
		final l = a - L_BASE, v = b - V_BASE;
		if (l >= 0 && l < L_COUNT && v >= 0 && v < V_COUNT)
			return S_BASE + (l * V_COUNT + v) * T_COUNT;
		final s = a - S_BASE, t = b - T_BASE;
		if (s >= 0 && s < S_COUNT && s % T_COUNT == 0 && t > 0 && t < T_COUNT)
			return a + t;
		final m = compositions.get(a);
		if (m == null)
			return -1;
		final c = m.get(b);
		return (c == null) ? -1 : c;
	}

	static inline function combiningClass(c:Int):Int {
		final cc = combiningClasses.get(c);
		return (cc == null) ? 0 : cc;
	}

	static function init() {
		UNASSIGNED = decodeRanges(StringPrepData.UNASSIGNED);
		MAPPED_TO_NOTHING = decodeRanges(StringPrepData.MAPPED_TO_NOTHING);
		NON_ASCII_SPACE = decodeRanges(StringPrepData.NON_ASCII_SPACE);
		RAND_AL_CAT = decodeRanges(StringPrepData.RAND_AL_CAT);
		L_CAT = decodeRanges(StringPrepData.L_CAT);
		combiningClasses = new Map();
		var v = decode(StringPrepData.COMBINING_CLASS), i = 0, start = 0;
		while (i < v.length) {
			start += v[i];
			for (c in start...start + v[i + 1] + 1)
				combiningClasses.set(c, v[i + 2]);
			i += 3;
		}
		compositions = new Map();
		v = decode(StringPrepData.COMPOSITION);
		i = 0;
		var first = 0;
		while (i < v.length) {
			first += v[i];
			var m = compositions.get(first);
			if (m == null)
				compositions.set(first, m = new Map());
			m.set(v[i + 1], v[i + 2]);
			i += 3;
		}
		decompositions = new Map();
		v = decode(StringPrepData.DECOMPOSITION);
		i = 0;
		var cp = 0;
		while (i < v.length) {
			cp += v[i];
			final len = v[i + 1];
			decompositions.set(cp, v.slice(i + 2, i + 2 + len));
			i += 2 + len;
		}
		PROHIBITED = decodeRanges(StringPrepData.PROHIBITED); // Last, marks init as complete
	}

	/**
		Decodes base 32 varints, digits of `MORE` continue a number and a digit of `TERMINAL` ends it.
	**/
	static function decode(chunks:Array<String>):Array<Int> {
		final out = new Array<Int>();
		var n = 0;
		for (chunk in chunks)
			for (i in 0...chunk.length) {
				final c = chunk.charAt(i);
				final t = TERMINAL.indexOf(c);
				if (t != -1) {
					out.push((n << 5) | t);
					n = 0;
				} else
					n = (n << 5) | MORE.indexOf(c);
			}
		return out;
	}

	/**
		Decodes ranges stored as `start - previous end, end - start, …`.
	**/
	static function decodeRanges(chunks:Array<String>):Array<Int> {
		final v = decode(chunks);
		for (i in 1...v.length)
			v[i] += v[i - 1];
		return v;
	}

	/**
		Binary search in flattened `[start, end, ...]` ranges.
	**/
	static function inRanges(c:Int, ranges:Array<Int>):Bool {
		var lo = 0, hi = (ranges.length >> 1) - 1;
		while (lo <= hi) {
			final mid = (lo + hi) >> 1;
			if (c < ranges[mid << 1])
				hi = mid - 1;
			else if (c > ranges[(mid << 1) + 1])
				lo = mid + 1;
			else
				return true;
		}
		return false;
	}
}
