# ODP_DPDK_PMDS(DPDK_DRIVER_PATH)
# -------------------------------
# Update DPDK_LIBS to include dependencies.
AC_DEFUN([ODP_DPDK_PMDS], [dnl
AC_MSG_NOTICE([Looking for DPDK PMDs at $1])
for filename in "$1"/librte_pmd_*.a; do
cur_driver=`basename "$filename" .a | sed -e 's/^lib//'`

# Match pattern is filled to 'filename' once if no matches are found
AS_IF([test "x$cur_driver" = "xrte_pmd_*"], [break])

AS_CASE([$cur_driver],
    [rte_pmd_nfp], [AS_VAR_APPEND([DPDK_LIBS], [" -lm"])],
    [rte_pmd_mlx4], [AS_VAR_APPEND([DPDK_LIBS], [" -lmlx4 -libverbs"])],
    [rte_pmd_mlx5], [AS_VAR_APPEND([DPDK_LIBS], [" -lmlx5 -libverbs -lmnl"])],
    [rte_pmd_pcap], [AS_VAR_APPEND([DPDK_LIBS], [" -lpcap"])],
    [rte_pmd_aesni_gcm], [AS_VAR_APPEND([DPDK_LIBS], [" -lIPSec_MB"])],
    [rte_pmd_aesni_mb], [AS_VAR_APPEND([DPDK_LIBS], [" -lIPSec_MB"])],
    [rte_pmd_kasumi], [AS_VAR_APPEND([DPDK_LIBS], [" -lsso_kasumi"])],
    [rte_pmd_snow3g], [AS_VAR_APPEND([DPDK_LIBS], [" -lsso_snow3g"])],
    [rte_pmd_zuc], [AS_VAR_APPEND([DPDK_LIBS], [" -lsso_zuc"])],
    [rte_pmd_qat], [AS_VAR_APPEND([DPDK_LIBS], [" -lcrypto"])],
    [rte_pmd_octeontx2], [AS_VAR_APPEND([DPDK_LIBS], [" -lm"])],
    [rte_pmd_openssl], [AS_VAR_APPEND([DPDK_LIBS], [" -lcrypto"])])
done

have_pmd_pcap=no
if [[ -f "$1"/librte_pmd_pcap.a ]]; then
    have_pmd_pcap=yes
fi
])

# _ODP_DPDK_SET_LIBS
# --------------------
# Set DPDK_LIBS/DPDK_LIBS_LT/DPDK_LIBS_LIBODP depending on DPDK setup
AC_DEFUN([_ODP_DPDK_SET_LIBS], [dnl
ODP_DPDK_PMDS([$DPDK_PMD_PATH])
DPDK_LIB="-Wl,--whole-archive,-ldpdk,--no-whole-archive"
AS_IF([test "x$DPDK_SHARED" = "xyes"], [dnl
    if test x$enable_static_applications != xyes; then
      if test $ODP_ABI_COMPAT -eq 1; then
        # applications don't need to be linked to anything, just rpath
        DPDK_LIBS_LT="$DPDK_RPATH_LT"
      else
        # dpdk symbols may be visible to applications
        DPDK_LIBS_LT="$DPDK_LDFLAGS -ldpdk"
      fi
    else
      # static linking flags will need -ldpdk
      DPDK_LIBS_LT="$DPDK_LDFLAGS $DPDK_LIB $DPDK_LIBS"
    fi
    DPDK_LIBS="-Wl,--no-as-needed,-ldpdk,--as-needed,`echo $DPDK_LIBS | sed -e 's/ /,/g'`"
    DPDK_LIBS="$DPDK_LDFLAGS $DPDK_RPATH $DPDK_LIBS"
    # link libodp-linux with -ldpdk
    DPDK_LIBS_LIBODP="$DPDK_LIBS"
], [dnl
    # build long list of libraries for applications, which should not be
    # rearranged by libtool
    DPDK_LIBS_LT="`echo $DPDK_LIBS | sed -e 's/^/-Wc,/' -e 's/ /,/g'`"
    DPDK_LIBS_LT="$DPDK_LDFLAGS $DPDK_LIB $DPDK_LIBS_LT $DPDK_LIBS"
    # static linking flags follow the suite
    DPDK_LIBS="$DPDK_LDFLAGS $DPDK_LIB $DPDK_LIBS"
    # link libodp-linux with libtool linking flags
    DPDK_LIBS_LIBODP="$DPDK_LIBS_LT"
])

OLD_LIBS=$LIBS
LIBS="-lnuma"
AC_TRY_LINK_FUNC([numa_num_configured_nodes],
		 [AC_DEFINE([_ODP_HAVE_NUMA_LIBRARY], [1],
			    [Define to 1 if numa library is usable])
		 AS_VAR_APPEND([DPDK_LIBS_LIBODP], [" -lnuma"])])
LIBS=$OLD_LIBS

AC_SUBST([DPDK_LIBS])
AC_SUBST([DPDK_LIBS_LIBODP])
AC_SUBST([DPDK_LIBS_LT])
])

# _ODP_DPDK_CHECK_LIB(LDFLAGS, [LIBS])
# ----------------------------------
# Check if one can use -ldpdk with provided set of libs
AC_DEFUN([_ODP_DPDK_CHECK_LIB], [dnl
##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_LDFLAGS=$LDFLAGS
OLD_LIBS=$LIBS
LDFLAGS="$1 $LDFLAGS"
LIBS="$LIBS -ldpdk $2"

AC_MSG_CHECKING([for rte_eal_init in -ldpdk $2])
AC_LINK_IFELSE([AC_LANG_CALL([], [rte_eal_init])],
	       [AC_MSG_RESULT([yes])
	        DPDK_LIBS="$2"],
	       [AC_MSG_RESULT([no])])

##########################################################################
# Restore old saved variables
##########################################################################
LDFLAGS=$OLD_LDFLAGS
LIBS=$OLD_LIBS
])

# _ODP_DPDK_CHECK(CPPFLAGS, LDFLAGS, ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
# ------------------------------------------------------------------------
# Check for DPDK availability
AC_DEFUN([_ODP_DPDK_CHECK], [dnl
##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$1 $CPPFLAGS"

dpdk_check_ok=yes

AC_CHECK_HEADERS([rte_config.h], [],
		 [dpdk_check_ok=no])

DPDK_LIBS=""
_ODP_DPDK_CHECK_LIB([$2], [-lm])
AS_IF([test "x$DPDK_LIBS" = "x"],
      [_ODP_DPDK_CHECK_LIB([$2], [-lm -ldl -lpthread])])
AS_IF([test "x$DPDK_LIBS" = "x"],
      [_ODP_DPDK_CHECK_LIB([$2], [-lm -ldl -lpthread -lnuma])])
AS_IF([test "x$DPDK_LIBS" = "x"],
      [dpdk_check_ok=no])
AS_IF([test "x$dpdk_check_ok" != "xno"],
      [_ODP_DPDK_SET_LIBS
       AC_SUBST([DPDK_CFLAGS])
       $3],
      [$4])

##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS
])

# _ODP_DPDK_LEGACY_SYSTEM(ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
# ------------------------------------------------------------------------
# Locate DPDK installation
AC_DEFUN([_ODP_DPDK_LEGACY_SYSTEM], [dnl
    DPDK_CFLAGS="-isystem /usr/include/dpdk"
    DPDK_LDFLAGS=""
    DPDK_LIB_PATH="`$CC $AM_CFLAGS $CFLAGS $AM_LDFLAGS $LDFLAGS --print-file-name=libdpdk.so`"
    if test "$DPDK_LIB_PATH" = "libdpdk.so" ; then
	DPDK_LIB_PATH="`$CC $AM_CFLAGS $CFLAGS $AM_LDFLAGS $LDFLAGS --print-file-name=libdpdk.a`"
        AS_IF([test "$DPDK_LIB_PATH" = "libdpdk.a"],
           [AC_MSG_FAILURE([Could not locate system DPDK library directory])])
    else
	DPDK_SHARED=yes
    fi
    DPDK_LIB_PATH=`AS_DIRNAME(["$DPDK_LIB_PATH"])`
    DPDK_PMD_PATH="$DPDK_LIB_PATH"
    AS_IF([test "x$DPDK_SHARED" = "xyes"],
	    [AC_MSG_NOTICE([Using shared DPDK library found at $DPDK_LIB_PATH])],
	    [AC_MSG_NOTICE([Using static DPDK library found at $DPDK_LIB_PATH])])
    _ODP_DPDK_CHECK([$DPDK_CFLAGS], [$DPDK_LDFLAGS], [$1], [$2])
])

# _ODP_DPDK_LEGACY(PATH, ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
# ------------------------------------------------------------------------
# Locate DPDK installation
AC_DEFUN([_ODP_DPDK_LEGACY], [dnl
    DPDK_CFLAGS="-isystem $1/include/dpdk"
    DPDK_LIB_PATH="$1/lib"
    DPDK_LDFLAGS="-L$DPDK_LIB_PATH"
    AS_IF([test -r "$DPDK_LIB_PATH"/libdpdk.so], [dnl
	DPDK_RPATH="-Wl,-rpath,$DPDK_LIB_PATH"
	DPDK_RPATH_LT="-R$DPDK_LIB_PATH"
	DPDK_SHARED=yes],
	[test ! -r "$DPDK_LIB_PATH"/libdpdk.a], [dnl
        AC_MSG_FAILURE([Could not find DPDK])])
    DPDK_PMD_PATH="$DPDK_LIB_PATH"
    AS_IF([test "x$DPDK_SHARED" = "xyes"],
	    [AC_MSG_NOTICE([Using shared DPDK library found at $DPDK_LIB_PATH])],
	    [AC_MSG_NOTICE([Using static DPDK library found at $DPDK_LIB_PATH])])
    _ODP_DPDK_CHECK([$DPDK_CFLAGS], [$DPDK_LDFLAGS], [$2], [$3])
])

m4_ifndef([PKG_CHECK_MODULES_STATIC],
[m4_define([PKG_CHECK_MODULES_STATIC],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
_save_PKG_CONFIG=$PKG_CONFIG
PKG_CONFIG="$PKG_CONFIG --static"
PKG_CHECK_MODULES($@)
PKG_CONFIG=$_save_PKG_CONFIG[]dnl
])])dnl PKG_CHECK_MODULES_STATIC

# _ODP_DPDK_PKGCONFIG (DPDK_SHARED, ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
# -----------------------------------------------------------------------
# Configure DPDK using pkg-config information
AC_DEFUN([_ODP_DPDK_PKGCONFIG], [dnl
use_pkg_config=no
dpdk_shared="$1"

if test "x$dpdk_shared" = "xyes" ; then
PKG_CHECK_MODULES([DPDK], [libdpdk],
                  [AC_MSG_NOTICE([Using shared DPDK lib via pkg-config])
                   use_pkg_config=yes
                   m4_default([$2], [:])],
                  [_ODP_DPDK_LEGACY_SYSTEM([m4_default([$2], [:])], [m4_default([$3], [:])])])
else
PKG_CHECK_MODULES_STATIC([DPDK], [libdpdk],
                         [AC_MSG_NOTICE([Using static DPDK lib via pkg-config])
                          use_pkg_config=yes
                          m4_default([$2], [:])],
                         [_ODP_DPDK_LEGACY_SYSTEM([m4_default([$2], [:])], [m4_default([$3], [:])])])
fi

if test "x$use_pkg_config" = "xyes"; then
    if test "x$dpdk_shared" = "xyes"; then
        DPDK_LIBS_LIBODP="$DPDK_LIBS"
        DPDK_LIBS_LT="$DPDK_LIBS"
        # Set RPATH if library path is found
        DPDK_LIB_PATH=$(echo "$DPDK_LIBS" | grep -o -- '-L\S*' | sed 's/^-L//')
        if test -n "$DPDK_LIB_PATH"; then
            DPDK_LIBS_LIBODP+=" -Wl,-rpath,$DPDK_LIB_PATH"
            # Debian / Ubuntu has relatively recently made new-dtags the
            # default, while others (e.g. Fedora) have not changed it. RPATH
            # is extended recursively when resolving transitive dependencies,
            # while RUNPATH (new-dtags) is not. We use RPATH to point to rte
            # libraries so that they can be found when PMDs are loaded in
            # rte_eal_init(). So we need to explicitly disable new-dtags.
            DPDK_LIBS_LT+=" -Wl,--disable-new-dtags -R$DPDK_LIB_PATH"
        fi
    else
        # Build a list of libraries, which should not be rearranged by libtool.
        # This ensures that DPDK constructors are included properly.
        DPDK_LIBS_LIBODP=$(echo "$DPDK_LIBS" | sed -e 's/\ *$//g' -e 's/ /,/g' -e 's/-Wl,//g')
        DPDK_LIBS_LIBODP=$(echo "$DPDK_LIBS_LIBODP" | sed 's/-pthread/-lpthread/g')
        DPDK_LIBS_LIBODP="-Wl,$DPDK_LIBS_LIBODP"
        DPDK_LIBS_LT="$DPDK_LIBS_LIBODP"
    fi
    DPDK_LIBS=$DPDK_LIBS_LIBODP

    # Use PKG_CHECK_MODULES_STATIC to look for rte_net_pcap in Libs.private
    PKG_CHECK_MODULES_STATIC([DPDK_STATIC], [libdpdk])
    have_pmd_pcap=no
    if grep -q "librte_net_pcap" <<< "$DPDK_STATIC_LIBS"; then
        have_pmd_pcap=yes
    fi

    # Include dpdk headers with -isystem instead of -I, to avoid a potentially
    # large number of warnings.
    DPDK_CFLAGS=$(echo $DPDK_CFLAGS | sed "s/-I/-isystem /")
fi
])

# ODP_DPDK(DPDK_PATH, DPDK_SHARED, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# --------------------------------------------------------------------------
# Check for DPDK availability
AC_DEFUN([ODP_DPDK], [dnl
AS_IF([test "x$1" = "xsystem"],
      [_ODP_DPDK_PKGCONFIG($2, [m4_default([$3], [:])], [m4_default([$4], [:])])],
      [_ODP_DPDK_LEGACY($1, [m4_default([$3], [:])], [m4_default([$4], [:])])]
    )
])
