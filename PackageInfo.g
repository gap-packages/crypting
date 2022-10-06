#
# crypting: Hashes and Crypto in GAP
#
# This file contains package meta data. For additional information on
# the meaning and correct usage of these fields, please consult the
# manual of the "Example" package as well as the comments in its
# PackageInfo.g file.
#
SetPackageInfo( rec(

PackageName := "crypting",
Subtitle := "Hashes and Crypto in GAP",
Version := "0.10.3",
Date := "06/10/2022", # dd/mm/yyyy format
License := "BSD-3-Clause",

Persons := [
  rec(
    IsAuthor := true,
    IsMaintainer := true,
    FirstNames := "Markus",
    LastName := "Pfeiffer",
    WWWHome := "http://www.morphism.de/~markusp/",
    Email := "markus.pfeiffer+gap@morphism.de",
    Place := "St Andrews",
  ),
  rec(
    LastName := "GAP Team",
    FirstNames := "The",
    IsAuthor := false,
    IsMaintainer := true,
    Email := "support@gap-system.org",
  ),
],

SourceRepository := rec(
    Type := "git",
    URL := Concatenation( "https://github.com/gap-packages/", ~.PackageName ),
),
IssueTrackerURL := Concatenation( ~.SourceRepository.URL, "/issues" ),
#SupportEmail   := "TODO",
PackageWWWHome  := "https://gap-packages.github.io/crypting/",
PackageInfoURL  := Concatenation( ~.PackageWWWHome, "PackageInfo.g" ),
README_URL      := Concatenation( ~.PackageWWWHome, "README.md" ),
ArchiveURL      := Concatenation( ~.SourceRepository.URL,
                                 "/releases/download/v", ~.Version,
                                 "/", ~.PackageName, "-", ~.Version ),

ArchiveFormats := ".tar.gz",

##  Status information. Currently the following cases are recognized:
##    "accepted"      for successfully refereed packages
##    "submitted"     for packages submitted for the refereeing
##    "deposited"     for packages for which the GAP developers agreed
##                    to distribute them with the core GAP system
##    "dev"           for development versions of packages
##    "other"         for all other packages
##
Status := "deposited",

AbstractHTML := "The <span class=\"pkgname\">crypting</span> package provides some cryptographic primitives so that the <span class=\"pkgname\">JupyterKernel</span> package works.",

JupyterKernelAbstractHTML   :=  "",

PackageDoc := rec(
  BookName  := "crypting",
  ArchiveURLSubset := ["doc"],
  HTMLStart := "doc/chap0_mj.html",
  PDFFile   := "doc/manual.pdf",
  SixFile   := "doc/manual.six",
  LongTitle := "Hashes and Crypto in GAP",
),

Dependencies := rec(
  GAP := ">= 4.10",
  NeededOtherPackages := [ [ "GAPDoc", ">= 1.5" ] ],
  SuggestedOtherPackages := [ ],
  ExternalConditions := [ ],
),

AvailabilityTest := function()
    if Filename(DirectoriesPackagePrograms("crypting"), "crypting.so") = fail then
 	return fail; 
    fi;	
    return true;
end,

TestFile := "tst/testall.g",

#Keywords := [ "TODO" ],

));


