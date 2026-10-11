import sasl.StringPrep;
import utest.Assert.*;

class TestStringPrep extends utest.Test {
	// https://www.rfc-editor.org/rfc/rfc4013#section-3
	function test_rfc4013() {
		equals('IX', StringPrep.prep('I­X'), 'SOFT HYPHEN mapped to nothing');
		equals('user', StringPrep.prep('user'), 'no transformation');
		equals('USER', StringPrep.prep('USER'), 'case preserved');
		equals('a', StringPrep.prep('ª'), 'output is NFKC');
		equals('IX', StringPrep.prep('Ⅸ'), 'output is NFKC');
		isNull(StringPrep.prep('\u0007'), 'prohibited character');
		isNull(StringPrep.prep('ا1'), 'bidirectional check');
	}

	function test_map() {
		equals('a b', StringPrep.prep('a b'), 'non-ASCII space mapped to space');
		equals('a b', StringPrep.prep('a　b'), 'non-ASCII space mapped to space');
		equals('a b', StringPrep.prep('a​b'), 'ZERO WIDTH SPACE is in C.1.2 and B.1');
		equals('ab', StringPrep.prep('a﻿b'), 'mapped to nothing');
		equals('ab', StringPrep.prep('a‍b'), 'mapped to nothing');
		equals('', StringPrep.prep(''));
		equals('', StringPrep.prep('­'));
		isNull(StringPrep.prep(null));
	}

	function test_normalize() {
		equals('Amélie', StringPrep.prep('Amélie'), 'composed');
		equals('Amélie', StringPrep.prep('Amélie'), 'decomposed');
		equals('ṩ', StringPrep.prep('ṩ'), 'canonical composition');
		equals('ṩ', StringPrep.prep('ṩ'), 'canonical reordering');
		equals('fi', StringPrep.prep('ﬁ'), 'compatibility decomposition');
		equals('ガ', StringPrep.prep('ｶﾞ'), 'halfwidth katakana');
		equals('A', StringPrep.prep('\u{1D400}'), 'mathematical bold');
		equals('한글', StringPrep.prep('한글'), 'hangul composition');
		equals('한글', StringPrep.prep('한글'), 'hangul syllables');
	}

	function test_prohibited() {
		for (s in ['\u0000', 'a\u001Fb', '\u007F', '\u0080', ' ', '', '\u{F0000}', '￿', '‎', '‪', '\u{E0001}', '⿰', '�'])
			isNull(StringPrep.prep(s), [for (c in new haxe.iterators.StringIteratorUnicode(s)) StringTools.hex(c, 4)].join(' '));
	}

	function test_bidi() {
		equals('אב', StringPrep.prep('אב'), 'RandALCat only');
		equals('ا1ب', StringPrep.prep('ا1ب'), 'RandALCat first and last');
		isNull(StringPrep.prep('1ا'), 'RandALCat not first');
		isNull(StringPrep.prep('اaب'), 'RandALCat and LCat');
	}

	function test_unassigned() {
		final emoji = '\u{1F600}';
		isNull(StringPrep.prep(emoji), 'unassigned in Unicode 3.2');
		isNull(StringPrep.prep('ȡ'));
		equals(emoji, StringPrep.prep(emoji, {allowUnassigned: true}));
		equals('pass' + emoji, StringPrep.prep('pass' + emoji, {allowUnassigned: true}));
		equals('ȡ', StringPrep.prep('ȡ', {allowUnassigned: true}));
		// Unassigned code points are not normalized
		equals('aٍٙ', StringPrep.prep('aٍٙ', {allowUnassigned: true}));
	}
}
