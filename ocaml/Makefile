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

BLOCKLIST=

OCAMLOPT=ocamlfind opt -package ctypes,ctypes.stubs -linkpkg -I lib
OCAMLDEP=ocamlfind dep -I lib -slash

OCAMLC=ocamlfind c -g -package ctypes,ctypes.stubs -linkpkg -I lib

CFLAGS += -I "$(shell ocamlfind query ctypes)" -I "$(shell ocamlfind c -where)"

# Don't include bindings for files that cannot be compiled.
BLOCKLIST_ML=$(patsubst %.c,%,$(BLOCKLIST))
ALL_OCAML=$(filter-out $(BLOCKLIST_ML),$(patsubst lib_gen/%_gen.ml,%,$(wildcard lib_gen/*_gen.ml)))

# Just names.
ALL_BINDINGS=$(patsubst %,lib/%_bindings.cmx,$(ALL_OCAML))
ALL_GENERATORS=$(patsubst %,lib_gen/%_gen.exe, $(ALL_OCAML))
ALL_ML_STUBS=$(patsubst %,lib/%_stubs.cmx,$(ALL_OCAML))
ALL_C_STUBS=$(patsubst %,lib/%_c_stubs.o,$(ALL_OCAML))

include .depend.ocaml
include ctypes.depend

lib_gen/Lib_RandomBuffer_System_gen.cmx: lib/Lib_RandomBuffer_System_bindings.cmx
lib_gen/Lib_RandomBuffer_System_gen.exe: lib/Lib_RandomBuffer_System_bindings.cmx lib_gen/Lib_RandomBuffer_System_gen.cmx

.depend.ocaml:
	$(OCAMLDEP) $(wildcard lib/*.ml) $(wildcard lib_gen/*.ml) > $@

# Note: for some reason, this minimal Makefile doesn't apply the shortest stem
# rule.
#
# %.exe:
# 	echo long stem
#
# %_foo.exe: %.b
# 	cat $<
#
# %.b:
# 	echo $@ > $@
#
# Which really puzzles me (e.g. make foo_foo.exe always echoes "long stem"),
# even though the shortest stem rule should apply. However, we can cancel a
# previous pattern rule, thanks to
# https://www.gnu.org/software/make/manual/html_node/Canceling-Rules.html
%.exe:

all: ocamlevercrypt.cmxa

lib_gen/%_gen.exe:
	$(OCAMLOPT) $(filter-out %.a,$^) libevercrypt.a -o $@

%.cmx: %.ml
	$(OCAMLOPT) -c $^ -o $@

%.cmo: %.ml
	$(OCAMLC) -c $^ -o $@


.PRECIOUS: lib/%_stubs.ml
lib/%_stubs.ml: lib/%_c_stubs.c

ifeq ($(shell uname -s),Darwin)
  DY=DYLD_LIBRARY_
else ifeq ($(OS),Windows_NT)
  DY=
else
  DY=LD_LIBRARY_
endif

lib/%_stubs.ml lib/%_c_stubs.c: lib_gen/%_gen.exe
	$<

# Compiling these files raises the pointer sign warning because the Ctypes declaration for bytes expects a char*, not a uint8_t*
# Can be remove once ctypes is upgraded to 0.17
lib/%_c_stubs.o: CFLAGS += -Wno-pointer-sign

BLOCKLIST_CMX =  $(patsubst %,lib/%_stubs.cmx,$(BLOCKLIST_ML))
BLOCKLIST_CMX += $(patsubst %,lib/%_bindings.cmx,$(BLOCKLIST_ML))
CTYPES_CMX    =  $(filter-out $(BLOCKLIST_CMX),$(CTYPES_DEPS))
CTYPES_CMX    += lib/Lib_RandomBuffer_System_stubs.cmx lib/Lib_RandomBuffer_System_bindings.cmx
CTYPES_ML     =  $(patsubst %.cmx,%.ml,$(CTYPES_CMX))
CTYPES_CMI    =  $(patsubst %.cmx,%.cmi,$(CTYPES_CMX))
CTYPES_CMO    = $(patsubst %.cmx,%.cmo,$(CTYPES_CMX))


ocamlevercrypt.cma: $(ALL_BINDINGS) $(CTYPES_CMO) $(ALL_C_STUBS) $(CTYPES_CMX) libevercrypt.$(SO)
	ocamlmklib -o ocamlevercrypt $(CTYPES_CMO) -L. -levercrypt

ocamlevercrypt.cmxa: $(ALL_BINDINGS) $(ALL_ML_STUBS) $(ALL_C_STUBS) libevercrypt.$(SO)
	ocamlmklib -o ocamlevercrypt $(CTYPES_CMX) -L. -levercrypt

STUBLIBS_PATH=$(OPAM_SWITCH_PREFIX)/lib/stublibs

dllocamlevercrypt.$(SO): ocamlevercrypt.cmxa ocamlevercrypt.cma
	ocamlmklib -o ocamlevercrypt $(ALL_C_STUBS) -L. -L$(STUBLIBS_PATH) -levercrypt

# install-hacl-star-raw: dllocamlevercrypt.$(SO)
# 	ocamlfind remove hacl-star-raw || true
# 	ocamlfind install hacl-star-raw META
# 	ocamlfind install -add hacl-star-raw $(CTYPES_ML)
# 	ocamlfind install -add hacl-star-raw $(CTYPES_CMX)
# 	ocamlfind install -add hacl-star-raw $(CTYPES_CMO)
# 	ocamlfind install -add hacl-star-raw $(CTYPES_CMI)
# 	ocamlfind install -add hacl-star-raw \
#          libevercrypt.a libevercrypt.$(SO) ocamlevercrypt.cma ocamlevercrypt.cmxa ocamlevercrypt.a \
#          libocamlevercrypt.a dllocamlevercrypt.$(SO) config.h

# .PHONY: install-ocaml
# install-ocaml: install-hacl-star-raw
# 	cd ../../bindings/ocaml && dune build && dune install
