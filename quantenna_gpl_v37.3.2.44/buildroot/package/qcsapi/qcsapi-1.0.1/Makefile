LIBOBJS = qcsapi_security.o qcsapi_wifi.o qcsapi_generic.o qcsapi_sem.o qcsapi_vsp.o \
	qcsapi_regulatory.o qcsapi_util.o

# Targets to build locally but not for sdk releases
PROGS += qpm

include Makefile.app

qpm: qpm.o
	$(build-prog-nolib)

%.o: Makefile.app

# Compilation of the dynamic libraries
$(DYNAMIC): $(LIBOBJS)
	$(call build-lib)

DOXYGEN_INPUT_DIRS = ./ ../../../../drivers/include/shared ../../../../include
Doxyfile: FORCE
	perl ../../../../common/doxygen/qtn_doxyfile.pl "Quantenna QCSAPI" "qcsapi" $(DOXYGEN_INPUT_DIRS) > $@

doxygen: Doxyfile
	doxygen
