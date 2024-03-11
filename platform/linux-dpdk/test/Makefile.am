include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/validation

if WITH_OPENSSL
TESTS_ENVIRONMENT += WITH_OPENSSL=1
else
TESTS_ENVIRONMENT += WITH_OPENSSL=0
endif

SUBDIRS =
TESTS =

if test_vald
TESTS += validation/api/pktio/pktio_run.sh

test_SCRIPTS = $(dist_check_SCRIPTS)

SUBDIRS += validation/api/pktio \
	   example \
	   performance

if WITH_ML
TESTS += validation/api/ml/ml_linux$(EXEEXT)
SUBDIRS += validation/api/ml
endif

else
#performance tests refer to pktio_env
if test_perf
SUBDIRS += validation/api/pktio \
	   performance
endif
endif

TEST_EXTENSIONS = .sh

TESTNAME = linux-dpdk

TESTENV = tests-$(TESTNAME).env

test_DATA = $(TESTENV)

DISTCLEANFILES = $(TESTENV)
.PHONY: $(TESTENV)
$(TESTENV):
	echo "TESTS=\"$(TESTS)\""    > $@
	echo "$(TESTS_ENVIRONMENT)" >> $@
	echo "$(LOG_COMPILER)"      >> $@
