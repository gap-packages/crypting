#
# crypting: Hashes and Crypto in GAP
#
# Declarations
#

DeclareCategory("IsSHA256State", IsObject);
# DeclareGlobalVariable("CRYPTING_SHA256_State_Family");
# DeclareGlobalVariable("CRYPTING_SHA256_State_Type", "State of SHA256");

DeclareGlobalFunction("CRYPTING_HexStringIntPad");
DeclareGlobalFunction("CRYPTING_HexStringIntPad8");


DeclareGlobalFunction("SHA256String");
