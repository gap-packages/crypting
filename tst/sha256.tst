gap> Concatenation(List(SHA256String("abc"), CRYPTING_HexStringIntPad8));
"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
gap> Concatenation(List(SHA256String("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), CRYPTING_HexStringIntPad8));
"248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"
gap> str := RepeatedString("The quick brown fox jumps over the lazy dog.\n", 5000);;
gap> Concatenation(List(SHA256String(str), CRYPTING_HexStringIntPad8));
"4BAFDB160ACD4142C07293E6955A4CE4B449D27C9A35FA56481BED84F9F2493E"
gap> SHA256String([(1,2)]);
Error, usage: str has to be a string
