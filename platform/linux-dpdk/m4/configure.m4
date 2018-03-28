IMPLEMENTATION_NAME="odp-dpdk"

ODP_VISIBILITY
ODP_ATOMIC

# linux-generic PCAP support is not relevant as the code doesn't use
# linux-generic pktio at all. And DPDK has its own PCAP support anyway
AM_CONDITIONAL([HAVE_PCAP], [false])
AM_CONDITIONAL([PKTIO_DPDK], [false])
ODP_PTHREAD
ODP_TIMER
ODP_OPENSSL
ODP_LIBCONFIG([linux-dpdk])
ODP_SCHEDULER

##########################################################################
# Set DPDK install path
##########################################################################
AC_ARG_WITH([dpdk-path],
[AS_HELP_STRING([--with-dpdk-path=DIR], [path to dpdk build directory])],
    [DPDK_PATH="$withval"],[DPDK_PATH=system])

##########################################################################
# Check for DPDK availability
#
# DPDK pmd drivers are not linked unless the --whole-archive option is
# used. No spaces are allowed between the --whole-arhive flags.
##########################################################################
ODP_DPDK([$DPDK_PATH], [],
	 [AC_MSG_FAILURE([can't find DPDK])])

case "${host}" in
  i?86* | x86*)
    DPDK_CPPFLAGS="${DPDK_CPPFLAGS} -msse4.2"
  ;;
esac

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([PLATFORM_IS_LINUX_DPDK],
	       [test "${with_platform}" = "linux-dpdk"])
AC_CONFIG_FILES([platform/linux-dpdk/Makefile
		 platform/linux-dpdk/libodp-linux.pc
		 platform/linux-dpdk/test/Makefile
		 platform/linux-dpdk/test/validation/api/pktio/Makefile])
])
