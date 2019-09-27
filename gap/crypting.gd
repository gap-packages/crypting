#
# crypting: Hashes and Crypto in GAP
#
# Declarations
#

#! @Chapter CryptinG Functions

#
#! @Section Internal Types and Functions
#

#!
DeclareCategory("IsSHA256State", IsObject);
# DeclareGlobalVariable("CRYPTING_SHA256_State_Family");
# DeclareGlobalVariable("CRYPTING_SHA256_State_Type", "State of SHA256");

#! @Description
#!   Call <Ref Label="HexStringInt" BookName="ref"/> on the argument <A>int</A>
#!   then pad the string on the left to <A>length</A> using padding
#!   letter <A>pad</A>
#! @Arguments int, pad, length
DeclareGlobalFunction("CRYPTING_HexStringIntPad");

#! @Description
#!   Call <Ref Label="HexStringInt" BookName="ref"/> on the argument <A>int</A>
#!   then pad the string on the left to length 8 using padding
#!   letter 0.
#! @Arguments int
DeclareGlobalFunction("CRYPTING_HexStringIntPad8");

#
#! @Section Hash functions
#

#! @Description
#!   Compute the SHA256 hash of the argument <A>string</A>
#!   in <C>IsStringRep</C>
#! @Arguments string
DeclareGlobalFunction("SHA256String");

#
#! @Section HMAC
#
# In principle HMAC should work with any hash if done right. Should
# probably look into doing that.
#

#! @Description
#!   Compute the HMAC SHA256 given a <A>key</A> and
#!   a <A>string</A> in <C>IsStringRep</C>.
#! @Arguments key, string
DeclareGlobalFunction("HMACSHA256");
