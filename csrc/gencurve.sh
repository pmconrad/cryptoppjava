#!/usr/bin/sh

mkdir -p ../build/generated/c
( cat <<__EOT__
#include "curves.h"

CryptoPP::OID curveByName(std::string name) {
__EOT__
  for i in $(awk 'BEGIN { parse = 0; FS = "\""; } \
                /"/ { if (parse) { print $2 " " $4  " " $6 " " $8; } } \
                / enum / { parse = 1; } \
                /;/ { parse = 0; }' < ../src/de/quisquis/ec/Curve.java); do
    echo "if (name == \"$i\") return CryptoPP::ASN1::$i();"
  done
  cat <<__EOT__
}
__EOT__
) >../build/generated/c/curves.cpp
