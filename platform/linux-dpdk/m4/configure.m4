ODP_IMPLEMENTATION_NAME="odp-dpdk"
ODP_LIB_NAME="odp-dpdk"

ODP_VISIBILITY
ODP_ATOMIC

m4_include([platform/linux-dpdk/m4/odp_cpu.m4])
m4_include([platform/linux-dpdk/m4/odp_event_validation.m4])
m4_include([platform/linux-dpdk/m4/odp_libconfig.m4])
m4_include([platform/linux-dpdk/m4/odp_openssl.m4])
m4_include([platform/linux-dpdk/m4/odp_pcapng.m4])
m4_include([platform/linux-dpdk/m4/odp_scheduler.m4])
m4_include([platform/linux-dpdk/m4/odp_wfe.m4])
m4_include([platform/linux-dpdk/m4/odp_ml.m4])

ODP_EVENT_VALIDATION
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
# Use shared DPDK library
##########################################################################
dpdk_shared=no
AC_ARG_ENABLE([dpdk-shared],
    [AS_HELP_STRING([--enable-dpdk-shared],
                    [use shared DPDK library [default=disabled] (linux-dpdk)])],
    [if test x$enableval = xyes; then
        dpdk_shared=yes
    fi])

##########################################################################
# Check for DPDK availability
#
# DPDK pmd drivers are not linked unless the --whole-archive option is
# used. No spaces are allowed between the --whole-archive flags.
##########################################################################
ODP_DPDK([$DPDK_PATH], [$dpdk_shared], [],
	 [AC_MSG_FAILURE([can't find DPDK])])
AM_CONDITIONAL([ODP_PKTIO_PCAP], [test x$have_pmd_pcap = xyes])

# In non-abi-compat mode DPDK is exposed to the application
if test $ODP_ABI_COMPAT -eq 1; then
	DPDK_LIBS_ABI_COMPAT=$DPDK_LIBS
	AC_SUBST([DPDK_LIBS_ABI_COMPAT])
else
	DPDK_LIBS_NON_ABI_COMPAT=$DPDK_LIBS
	AC_SUBST([DPDK_LIBS_NON_ABI_COMPAT])
	# DPDK uses strnlen() internally
	DPDK_CFLAGS="${DPDK_CFLAGS} -D_GNU_SOURCE"
fi

case "${host}" in
  i?86* | x86*)
    DPDK_CFLAGS="${DPDK_CFLAGS} -msse4.2"
  ;;
esac

# Required for experimental rte_event_port_unlinks_in_progress() API
DPDK_CFLAGS="${DPDK_CFLAGS} -DALLOW_EXPERIMENTAL_API"

AS_VAR_APPEND([PLAT_DEP_LIBS], ["${ATOMIC_LIBS} ${LIBCONFIG_LIBS} ${OPENSSL_LIBS} ${DPDK_LIBS_LT} ${LIBCLI_LIBS} ${ORT_LIBS}"])

# Add text to the end of configure with platform specific settings.
# Make sure it's aligned same as other lines in configure.ac.
AS_VAR_APPEND([PLAT_CFG_TEXT], ["
	event_validation:       ${enable_event_validation}
	openssl:                ${with_openssl}
	openssl_rand:           ${openssl_rand}
	pcap:                   ${have_pmd_pcap}
	pcapng:                 ${have_pcapng}
	wfe_locks:              ${use_wfe_locks}
	ml_support:             ${ml_support}
	default_config_path:    ${default_config_path}"])

ODP_CHECK_CFLAG([-Wno-error=cast-align])

# Ignore Clang specific errors about fields with variable sized type not at the
# end of a struct or usage of these structs in arrays. This style is used by
# e.g. timer_pool_t.
ODP_CHECK_CFLAG([-Wno-error=gnu-variable-sized-type-not-at-end])
ODP_CHECK_CFLAG([-Wno-error=flexible-array-extensions])

AC_DEFINE([_ODP_PKTIO_DPDK], [1])
AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([PLATFORM_IS_LINUX_DPDK],
	       [test "${with_platform}" = "linux-dpdk"])
AC_CONFIG_FILES([platform/linux-dpdk/Makefile
		 platform/linux-dpdk/libodp-dpdk.pc
		 platform/linux-dpdk/dumpconfig/Makefile
		 platform/linux-dpdk/example/Makefile
		 platform/linux-dpdk/example/ml/Makefile
		 platform/linux-dpdk/test/Makefile
		 platform/linux-dpdk/test/example/Makefile
		 platform/linux-dpdk/test/example/classifier/Makefile
		 platform/linux-dpdk/test/example/generator/Makefile
		 platform/linux-dpdk/test/example/ipsec_api/Makefile
		 platform/linux-dpdk/test/example/ipsec_crypto/Makefile
		 platform/linux-dpdk/test/example/l2fwd_simple/Makefile
		 platform/linux-dpdk/test/example/l3fwd/Makefile
		 platform/linux-dpdk/test/example/packet/Makefile
		 platform/linux-dpdk/test/example/ping/Makefile
		 platform/linux-dpdk/test/example/simple_pipeline/Makefile
		 platform/linux-dpdk/test/example/switch/Makefile
		 platform/linux-dpdk/test/performance/Makefile
		 platform/linux-dpdk/test/performance/dmafwd/Makefile
		 platform/linux-dpdk/test/validation/api/ml/Makefile
		 platform/linux-dpdk/test/validation/api/pktio/Makefile])
])
