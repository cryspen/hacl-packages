#    Copyright 2022 Cryspen Sarl
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# This file is adapted from the project-everest/hacl-star/ Makefile.

.PRECIOUS: %.cmx

all: setup ocamlevercrypt.cmxa build

UNAME		?= $(shell uname)
ifeq ($(UNAME),Darwin)
  SO		= dylib
  OCAML_SO	= so
else ifeq ($(UNAME),Linux)
  SO 		= so
  OCAML_SO	= so
else ifeq ($(OS),Windows_NT)
  $(error "Windows is not supported at the moment.")
else ifeq ($(UNAME),FreeBSD)
  SO 		= so
  OCAML_SO	= so
endif

# Config
# TODO: Read this from the main config.
STATIC_C_LIB_NAME=hacl_static
DYNAMIC_C_LIB_NAME=hacl
BLOCKLIST_NON_X64=EverCrypt_Vale.c
BLOCKLIST=Hacl_Bignum256_32.c Hacl_Bignum256.c Hacl_Bignum32.c Hacl_Bignum4096_32.c Hacl_Bignum4096.c Hacl_Bignum.c Hacl_Bignum64.c Hacl_Bignum_Base.c Hacl_GenericField32.c Hacl_GenericField64.c
BLOCKLIST+=$(BLOCKLIST_NON_X64)
BLOCKLIST+=Hacl_Curve25519_64.c Hacl_HPKE_Curve64_CP128_SHA256.c Hacl_HPKE_Curve64_CP128_SHA512.c Hacl_HPKE_Curve64_CP256_SHA256.c Hacl_HPKE_Curve64_CP256_SHA512.c Hacl_HPKE_Curve64_CP32_SHA256.c Hacl_HPKE_Curve64_CP32_SHA512.c
BLOCKLIST+=evercrypt_vale_stubs.c
BLOCKLIST+=Hacl_Chacha20Poly1305_256.c Hacl_Chacha20_Vec256.c Hacl_HKDF_Blake2b_256.c Hacl_HMAC_Blake2b_256.c Hacl_HPKE_Curve51_CP256_SHA256.c Hacl_HPKE_Curve51_CP256_SHA512.c Hacl_HPKE_Curve64_CP256_SHA256.c Hacl_HPKE_Curve64_CP256_SHA512.c Hacl_HPKE_P256_CP256_SHA256.c Hacl_Hash_Blake2b_256.c Hacl_Poly1305_256.c Hacl_SHA2_Vec256.c Hacl_Streaming_Blake2b_256.c Hacl_Streaming_Poly1305_256.c
C_PATH?=c
C_LIB_PATH?=$(C_PATH)/lib/
C_LIB?=$(C_LIB_PATH)lib$(STATIC_C_LIB_NAME).a
C_DYN_LIB?=$(C_LIB_PATH)lib$(DYNAMIC_C_LIB_NAME).$(SO) # FIXME
C_INCLUDES?=-Ic/include/hacl/ \
			-Ic/include/vale/ \
			-Ic/include/ \
			-I../include/ # XXX: internal is used in lib/
KARAMEL_INCLUDES?=-Ic/include/kremlin/include \
				  -Ic/include/kremlin/kremlib/dist/minimal/

OCAMLOPT=ocamlfind opt -package ctypes,ctypes.stubs -linkpkg -I lib
OCAMLDEP=ocamlfind dep -I lib -slash

OCAMLC=ocamlfind c -g -package ctypes,ctypes.stubs -linkpkg -I lib

CFLAGS += -I "$(shell ocamlfind query ctypes)" -I "$(shell ocamlfind c -where)" \
		  $(C_INCLUDES) $(KARAMEL_INCLUDES)

# Don't include bindings for files that cannot be compiled.
BLOCKLIST_ML=$(patsubst %.c,%,$(BLOCKLIST))
ALL_OCAML=$(filter-out $(BLOCKLIST_ML),$(patsubst lib_gen/%_gen.ml,%,$(wildcard lib_gen/*_gen.ml)))

# File names.
ALL_BINDINGS=$(patsubst %,lib/%_bindings.cmx,$(ALL_OCAML))
ALL_GENERATORS=$(patsubst %,lib_gen/%_gen.exe, $(ALL_OCAML))
ALL_ML_STUBS=$(patsubst %,lib/%_stubs.cmx,$(ALL_OCAML))
ALL_C_STUBS=$(patsubst %,lib/%_c_stubs.o,$(ALL_OCAML))

include .depend.ocaml
include ctypes.depend

# - copy and clean config.h
setup:
ifeq ($(wildcard $(C_PATH)),)
		mkdir $(C_PATH)
		cp -r ../build/installed/* $(C_PATH)/
		cp $(C_LIB) .
		sed -ri '/(\/\/.*)|(\/\*.*\*\/)/d' ./c/include/hacl/config.h
endif

# ifeq ("$(wildcard $(C_LIB))","")
# $(error I couldn't find the C library $(C_LIB). Please build it first or tell me where to find it.)
# endif

lib_gen/Lib_RandomBuffer_System_gen.cmx: lib/Lib_RandomBuffer_System_bindings.cmx
lib_gen/Lib_RandomBuffer_System_gen.exe: lib/Lib_RandomBuffer_System_bindings.cmx lib_gen/Lib_RandomBuffer_System_gen.cmx

.depend.ocaml:
	$(OCAMLDEP) $(wildcard lib/*.ml) $(wildcard lib_gen/*.ml) > $@

%.exe:

lib_gen/%_gen.exe:
	$(OCAMLOPT) $(filter-out %.a,$^) $(C_LIB) -o $@

%.cmx: %.ml
	$(OCAMLOPT) -c $^ -o $@

%.cmo: %.ml
	$(OCAMLC) -c $^ -o $@


.PRECIOUS: lib/%_stubs.ml
lib/%_stubs.ml: lib/%_c_stubs.c

lib/%_stubs.ml lib/%_c_stubs.c: lib_gen/%_gen.exe
	$<

BLOCKLIST_CMX =  $(patsubst %,lib/%_stubs.cmx,$(BLOCKLIST_ML))
BLOCKLIST_CMX += $(patsubst %,lib/%_bindings.cmx,$(BLOCKLIST_ML))
CTYPES_CMX    =  $(filter-out $(BLOCKLIST_CMX),$(CTYPES_DEPS))
CTYPES_CMX    += lib/Lib_RandomBuffer_System_stubs.cmx lib/Lib_RandomBuffer_System_bindings.cmx
CTYPES_ML     =  $(patsubst %.cmx,%.ml,$(CTYPES_CMX))
CTYPES_CMI    =  $(patsubst %.cmx,%.cmi,$(CTYPES_CMX))
CTYPES_CMO    = $(patsubst %.cmx,%.cmo,$(CTYPES_CMX))


ocamlevercrypt.cma: $(ALL_BINDINGS) $(CTYPES_CMO) $(ALL_C_STUBS) $(CTYPES_CMX)
	ocamlmklib -o ocamlevercrypt $(CTYPES_CMO) -L. -l$(STATIC_C_LIB_NAME)

ocamlevercrypt.cmxa: $(ALL_BINDINGS) $(ALL_ML_STUBS) $(ALL_C_STUBS)
	ocamlmklib -o ocamlevercrypt $(CTYPES_CMX) -L. -l$(STATIC_C_LIB_NAME)

STUBLIBS_PATH=$(OPAM_SWITCH_PREFIX)/lib/stublibs

dllocamlevercrypt.$(OCAML_SO): ocamlevercrypt.cmxa ocamlevercrypt.cma
	ocamlmklib -o ocamlevercrypt $(ALL_C_STUBS) -L. -L$(STUBLIBS_PATH) -l$(STATIC_C_LIB_NAME)

clean:
	rm -rf *.$(SO) *.$(OCAML_SO) *.a .depend.ocaml *.cmxa *.cma \
	**/*.cma **/*.cmo **/*.cmx **/*.cmxa* **/*.o **/*.c **/*.cmi **/*.exe **/*.o **/*.d \
	rm -rf c rm -rf hacl-star/_build

# Install hacl-star-raw locally.
# XXX: There must be a better way.
install-hacl-star-raw: dllocamlevercrypt.$(OCAML_SO)
	ocamlfind remove hacl-star-raw || true
	ocamlfind install hacl-star-raw META
	ocamlfind install -add hacl-star-raw $(CTYPES_ML)
	ocamlfind install -add hacl-star-raw $(CTYPES_CMX)
	ocamlfind install -add hacl-star-raw $(CTYPES_CMO)
	ocamlfind install -add hacl-star-raw $(CTYPES_CMI)
	ocamlfind install -add hacl-star-raw \
         $(C_LIB) $(C_DYN_LIB) \
		 ocamlevercrypt.cma ocamlevercrypt.cmxa ocamlevercrypt.a \
         libocamlevercrypt.a dllocamlevercrypt.$(OCAML_SO) c/include/hacl/config.h

.PHONY: install-ocaml
build: install-hacl-star-raw
	cd hacl-star && dune build

test: build
	cd hacl-star && dune test
