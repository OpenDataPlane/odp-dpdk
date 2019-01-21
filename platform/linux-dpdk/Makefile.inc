AM_CFLAGS += $(DPDK_CFLAGS)
AM_CXXFLAGS += $(DPDK_CFLAGS)

LOG_COMPILER = $(top_srcdir)/platform/linux-dpdk/test/wrapper-script.sh
SH_LOG_COMPILER = $(LOG_COMPILER)
dist_check_SCRIPTS = $(top_srcdir)/platform/linux-dpdk/test/wrapper-script.sh
