AM_CFLAGS += $(DPDK_CFLAGS)
AM_CXXFLAGS += $(DPDK_CFLAGS)

LOG_COMPILER = $(top_builddir)/platform/linux-dpdk/test/wrapper-script.sh
SH_LOG_COMPILER = $(LOG_COMPILER)
EXTRA_DIST += $(top_builddir)/platform/linux-dpdk/test/wrapper-script.sh
