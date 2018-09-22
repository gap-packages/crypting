#
# crypting: Hashes and Crypto in GAP
#
# Implementations
#

BindGlobal("CRYPTING_SHA256_State_Family",
           NewFamily("CRYPTING_SHA256_State_Family"));


BindGlobal("CRYPTING_SHA256_State_Type",
           NewType(CRYPTING_SHA256_State_Family,
                   IsSHA256State) );


InstallGlobalFunction( CRYPTING_HexStringIntPad,
function(i, len, pad)
    local result;

    result := HexStringInt(i);
    if Length(result) < len then
        result := Concatenation(RepeatedString(pad,len - Length(result)), result);
    fi;
    return result;
end);

InstallGlobalFunction( CRYPTING_HexStringIntPad8,
    i -> CRYPTING_HexStringIntPad(i, 8, '0'));

InstallMethod( ViewString, "for a SHA256 state",
               [ IsSHA256State ], x -> "<sha256 state>");

InstallGlobalFunction( SHA256String,
function(str)
    local s;

    if not IsString(str) then
        ErrorNoReturn("usage: str has to be a string");
    fi;

    str := CopyToStringRep(str);
    s := CRYPTING_SHA256_INIT();
    CRYPTING_SHA256_UPDATE(s, str);
    return CRYPTING_SHA256_FINAL(s);
end);

InstallGlobalFunction( HMACSHA256,
function(key, str)
    if not IsString(key) then
        ErrorNoReturn("usage: key has to be a string");
    fi;
    if not IsString(str) then
        ErrorNoReturn("usage: str has to be a string");
    fi;
    key := CopyToStringRep(str);
    str := CopyToStringRep(str);
    return CRYPTING_SHA256_HMAC(key, str);
end);
