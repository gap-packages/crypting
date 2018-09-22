gap> Concatenation(List(CRYPTING_SHA256_HMAC("",""), CRYPTING_HexStringIntPad8));
"B613679A0814D9EC772F95D778C35FC5FF1697C493715653C6C712144292C5AD"
gap> Concatenation(List(CRYPTING_SHA256_HMAC("key", "The quick brown fox jumps over the lazy dog"), CRYPTING_HexStringIntPad8));
"F7BC83F430538424B13298E6AA6FB143EF4D59A14946175997479DBC2D1A3CD8"
gap> str := RepeatedString("The quick brown fox jumps over the lazy dog.\n", 5000);;
gap> Concatenation(List(CRYPTING_SHA256_HMAC("key", str), CRYPTING_HexStringIntPad8));
"9319843BE4B7BBD7928B3DD7080B37E4CD46F9DC244812E3DD6783CF56C25AEE"
gap> Concatenation(List(CRYPTING_SHA256_HMAC(str, str), CRYPTING_HexStringIntPad8));
"9DC5FB7ECE7CC15F9DF778BA562ACAEDA325459C8CC0546AFB4A70EB6EE5E703"
gap> HMACSHA256(15,"bla");
Error, usage: key has to be a string
gap> HMACSHA256("abc", 15);
Error, usage: str has to be a string
gap> CRYPTING_SHA256_HMAC("", "");
[ 3054725018, 135584236, 1999607255, 2026069957, 4279670724, 2473678419, 
  3334935060, 1116915117 ]
gap> CRYPTING_SHA256_HMAC(['a'], 5);
Error, usage: key has to be a string in IsStringRep
