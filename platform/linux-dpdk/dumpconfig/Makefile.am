include $(top_srcdir)/Makefile.inc

AM_CPPFLAGS =  -I$(top_builddir)/platform/$(with_platform)/include
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/include

bin_PROGRAMS = odp_linuxdpdk_dumpconfig

odp_linuxdpdk_dumpconfig_SOURCES = ../../linux-generic/dumpconfig/dumpconfig.c

TESTS = odp_linuxdpdk_dumpconfig
