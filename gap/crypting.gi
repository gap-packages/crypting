#
# crypting: Hashes and Crypto in GAP
#
# Implementations
#

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

