include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/validation

SUBDIRS =

if test_vald
TESTS = validation/api/pktio/pktio_run.sh

test_SCRIPTS = $(dist_check_SCRIPTS)

SUBDIRS += validation/api/pktio \
	   example
else
#performance tests refer to pktio_env
if test_perf
SUBDIRS += validation/api/pktio
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

if test_installdir
installcheck-local:
	$(DESTDIR)/$(testdir)/run-test.sh $(TESTNAME)
endif

# If building out-of-tree, make check will not copy the scripts and data to the
# $(builddir) assuming that all commands are run locally. However this prevents
# running tests on a remote target using LOG_COMPILER.
# So copy all script and data files explicitly here.
all-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(dist_check_SCRIPTS); do \
			if [ -e $(srcdir)/$$f ]; then \
				mkdir -p $(builddir)/$$(dirname $$f); \
				cp -f $(srcdir)/$$f $(builddir)/$$f; \
			fi \
		done \
	fi
clean-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(dist_check_SCRIPTS); do \
			rm -f $(builddir)/$$f; \
		done \
	fi

.NOTPARALLEL:
