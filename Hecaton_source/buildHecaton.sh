#!/usr/bin/env bash

set -e

MYClang_dir=$(cd "../compilers/clang/bin"; printf %s "$PWD")
MYInclude_dir=$(cd "../compilers/clang/include"; printf %s "$PWD")

MYClangxx=$MYClang_dir/clang++
MYLLVMConfig=./llvm-config

echo "$MYInclude_dir"

"$MYClangxx" -v -I"$MYInclude_dir" -std=c++14 HecatonDatabase.cpp \
  $("$MYLLVMConfig" --cxxflags --ldflags) \
  -fPIC -o hecaton_database.so -shared -Wl,-undefined,dynamic_lookup

"$MYClangxx" -v -I"$MYInclude_dir" -std=c++14 HecatonPass1.cpp \
  $("$MYLLVMConfig" --cxxflags --ldflags) \
  -fPIC -o hecaton_pass1.so -shared -Wl,-undefined,dynamic_lookup

"$MYClangxx" -v -I"$MYInclude_dir" -std=c++14 HecatonPass2.cpp \
  $("$MYLLVMConfig" --cxxflags --ldflags) \
  -fPIC -o hecaton_pass2.so -shared -Wl,-undefined,dynamic_lookup
