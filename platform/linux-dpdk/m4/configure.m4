ODP_IMPLEMENTATION_NAME="odp-dpdk"
ODP_LIB_NAME="odp-dpdk"

ODP_VISIBILITY
ODP_ATOMIC

m4_include([platform/linux-dpdk/m4/odp_libconfig.m4])
m4_include([platform/linux-dpdk/m4/odp_pcapng.m4])
m4_include([platform/linux-dpdk/m4/odp_scheduler.m4])

ODP_PTHREAD
ODP_SCHEDULER
ODP_TIMER

##########################################################################
# Set DPDK install path
##########################################################################
AC_ARG_WITH([dpdk-path],
[AS_HELP_STRING([--with-dpdk-path=DIR],
		[path to DPDK build directory [default=system] (linux-dpdk)])],
    [DPDK_PATH="$withval"],[DPDK_PATH=system])

##########################################################################
# Check for DPDK availability
#
# DPDK pmd drivers are not linked unless the --whole-archive option is
# used. No spaces are allowed between the --whole-arhive flags.
##########################################################################
ODP_DPDK([$DPDK_PATH], [],
	 [AC_MSG_FAILURE([can't find DPDK])])
AM_CONDITIONAL([ODP_PKTIO_PCAP], [test x$have_pmd_pcap = xyes])

# In non-abi-compat mode DPDK is exposed to the application
if test $ODP_ABI_COMPAT -eq 1; then
	DPDK_LIBS_ABI_COMPAT=$DPDK_LIBS
	AC_SUBST([DPDK_LIBS_ABI_COMPAT])
else
	DPDK_LIBS_NON_ABI_COMPAT=$DPDK_LIBS
	AC_SUBST([DPDK_LIBS_NON_ABI_COMPAT])
fi

case "${host}" in
  i?86* | x86*)
    DPDK_CFLAGS="${DPDK_CFLAGS} -msse4.2"
  ;;
esac

# Required for experimental rte_event_port_unlinks_in_progress() API
DPDK_CFLAGS="${DPDK_CFLAGS} -DALLOW_EXPERIMENTAL_API"

AS_VAR_APPEND([PLAT_DEP_LIBS], ["${LIBCONFIG_LIBS} ${OPENSSL_LIBS} ${DPDK_LIBS_LT}"])

# Add text to the end of configure with platform specific settings.
# Make sure it's aligned same as other lines in configure.ac.
AS_VAR_APPEND([PLAT_CFG_TEXT], ["
	pcap:			${have_pmd_pcap}
	pcapng:			${have_pcapng}
	default_config_path:	${default_config_path}"])

ODP_CHECK_CFLAG([-Wno-error=cast-align])
AC_DEFINE([_ODP_PKTIO_DPDK], [1])
AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([PLATFORM_IS_LINUX_DPDK],
	       [test "${with_platform}" = "linux-dpdk"])
AC_CONFIG_FILES([platform/linux-dpdk/Makefile
		 platform/linux-dpdk/libodp-dpdk.pc
		 platform/linux-dpdk/dumpconfig/Makefile
		 platform/linux-dpdk/test/Makefile
		 platform/linux-dpdk/test/example/Makefile
		 platform/linux-dpdk/test/example/generator/Makefile
		 platform/linux-dpdk/test/example/l2fwd_simple/Makefile
		 platform/linux-dpdk/test/example/l3fwd/Makefile
		 platform/linux-dpdk/test/example/packet/Makefile
		 platform/linux-dpdk/test/example/ping/Makefile
		 platform/linux-dpdk/test/example/simple_pipeline/Makefile
		 platform/linux-dpdk/test/example/switch/Makefile
		 platform/linux-dpdk/test/validation/api/pktio/Makefile])
])
