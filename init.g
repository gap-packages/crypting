#
# crypting: Hashes and Crypto in GAP
#
# Reading the declaration part of the package.
#

if not LoadKernelExtension("crypting") then
  Error("failed to load the crypting package kernel extension");
fi;

ReadPackage( "crypting", "gap/crypting.gd");
