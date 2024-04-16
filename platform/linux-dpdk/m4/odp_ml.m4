##########################################################################
# DPDK ML API
##########################################################################
AC_DEFUN([ODP_ML], [dnl

ml_support=no
ml_option=yes
AC_ARG_ENABLE([dpdk-ml],
	[AS_HELP_STRING([--disable-dpdk-ml],
			[disable ML support]
			[[default=enabled] (linux-dpdk)])],
	[if test "x$enableval" = "xno"; then
		ml_option=no
	fi])

AS_IF([test "x$ml_option" != "xno"], [dnl

#########################################################################
# If dpdk mldev header is available, enable ML API
#########################################################################
OLD_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$DPDK_CFLAGS $CPPFLAGS"
AC_CHECK_HEADERS([rte_mldev.h], [ml_support=yes], [], [])
CPPFLAGS=$OLD_CPPFLAGS

])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([WITH_ML], [test x$ml_support = xyes])
])

# Even if ML is not enabled, -lm is needed by quantization.
ML_LIBS="-lm"
AC_SUBST([ML_LIBS])

]) # ODP_ML
