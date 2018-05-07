include $(top_srcdir)/platform/Makefile.inc
include $(top_srcdir)/platform/@with_platform@/Makefile.inc

AM_CPPFLAGS  =  $(ODP_INCLUDES)
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/include
AM_CPPFLAGS +=  -I$(top_builddir)/platform/$(with_platform)/include
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/linux-generic/include
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/arch
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/arch/@ARCH_DIR@
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/arch/default

AM_CPPFLAGS +=  $(OPENSSL_CPPFLAGS)
AM_CPPFLAGS +=  $(DPDK_CPPFLAGS)

AM_CFLAGS +=  $(LIBCONFIG_CFLAGS)

DISTCLEANFILES = include/odp_libconfig_config.h
include/odp_libconfig_config.h: $(top_srcdir)/config/odp-$(with_platform).conf $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@

if !ODP_ABI_COMPAT
odpapiplatincludedir= $(includedir)/odp/api/plat
odpapiplatinclude_HEADERS = \
		  include/odp/api/plat/atomic_inlines.h \
		  include/odp/api/plat/buffer_inline_types.h \
		  include/odp/api/plat/byteorder_inlines.h \
		  include/odp/api/plat/byteorder_inlines_api.h \
		  include/odp/api/plat/event_inlines.h \
		  include/odp/api/plat/packet_flag_inlines.h \
		  include/odp/api/plat/packet_flag_inlines_api.h \
		  include/odp/api/plat/packet_inline_types.h \
		  include/odp/api/plat/packet_inlines.h \
		  include/odp/api/plat/packet_inlines_api.h \
		  include/odp/api/plat/pktio_inlines.h \
		  include/odp/api/plat/pktio_inlines_api.h \
		  include/odp/api/plat/pool_inline_types.h \
		  include/odp/api/plat/std_clib_inlines.h \
		  include/odp/api/plat/strong_types.h \
		  include/odp/api/plat/sync_inlines.h \
		  include/odp/api/plat/thread_inlines.h \
		  include/odp/api/plat/thread_inlines_api.h \
		  include/odp/api/plat/ticketlock_inlines.h \
		  include/odp/api/plat/ticketlock_inlines_api.h

odpapiabiarchincludedir = $(archincludedir)/odp/api/abi
odpapiabiarchinclude_HEADERS = \
		  include-abi/odp/api/abi/align.h \
		  include-abi/odp/api/abi/atomic.h \
		  include-abi/odp/api/abi/barrier.h \
		  include-abi/odp/api/abi/buffer.h \
		  include-abi/odp/api/abi/byteorder.h \
		  include-abi/odp/api/abi/classification.h \
		  include-abi/odp/api/abi/cpumask.h \
		  include-abi/odp/api/abi/crypto.h \
		  include-abi/odp/api/abi/debug.h \
		  include-abi/odp/api/abi/event.h \
		  include-abi/odp/api/abi/init.h \
		  include-abi/odp/api/abi/ipsec.h \
		  include-abi/odp/api/abi/packet.h \
		  include-abi/odp/api/abi/packet_flags.h \
		  include-abi/odp/api/abi/packet_io.h \
		  include-abi/odp/api/abi/pool.h \
		  include-abi/odp/api/abi/queue.h \
		  include-abi/odp/api/abi/rwlock.h \
		  include-abi/odp/api/abi/rwlock_recursive.h \
		  include-abi/odp/api/abi/schedule.h \
		  include-abi/odp/api/abi/schedule_types.h \
		  include-abi/odp/api/abi/shared_memory.h \
		  include-abi/odp/api/abi/spinlock.h \
		  include-abi/odp/api/abi/spinlock_recursive.h \
		  include-abi/odp/api/abi/std_clib.h \
		  include-abi/odp/api/abi/std_types.h \
		  include-abi/odp/api/abi/sync.h \
		  include-abi/odp/api/abi/thread.h \
		  include-abi/odp/api/abi/thrmask.h \
		  include-abi/odp/api/abi/ticketlock.h \
		  include-abi/odp/api/abi/time.h \
		  include-abi/odp/api/abi/timer.h \
		  include-abi/odp/api/abi/traffic_mngr.h \
		  include-abi/odp/api/abi/version.h
endif

noinst_HEADERS = \
		  arch/odp_arch_time_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_align_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_atomic_internal.h \
		  include/odp_buffer_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_bitmap_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_bitset.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_internal.h \
		  include/odp_config_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_debug_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_datamodel.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_inlines.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_internal.h \
		  include/odp_eventdev_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_forward_typedefs_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_ipsec_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_libconfig_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_llqueue.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_macros_internal.h \
		  include/odp_packet_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_name_table_internal.h \
		  include/odp_packet_io_internal.h \
		  include/odp_errno_define.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_ipc_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_ring_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_socket.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_null.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_pcapng.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_pkt_queue_internal.h \
		  include/odp_pool_internal.h \
		  include/odp_posix_extensions.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_queue_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_queue_if.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_queue_lf.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_ring_internal.h \
		  include/odp_ring_st_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_schedule_if.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_sorted_list_internal.h \
		  include/odp_shm_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_timer_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_timer_wheel_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_traffic_mngr_internal.h \
		  include/protocols/eth.h \
		  include/protocols/ip.h \
		  include/protocols/ipsec.h \
		  include/protocols/tcp.h \
		  include/protocols/thash.h \
		  include/protocols/udp.h \
		  Makefile.inc

nodist_noinst_HEADERS = \
		  include/odp_libconfig_config.h

__LIB__libodp_linux_la_SOURCES = \
			   ../linux-generic/odp_atomic.c \
			   ../linux-generic/odp_barrier.c \
			   ../linux-generic/odp_bitmap.c \
			   odp_buffer.c \
			   ../linux-generic/odp_chksum.c \
			   ../linux-generic/odp_classification.c \
			   ../linux-generic/odp_cpu.c \
			   ../linux-generic/odp_cpumask.c \
			   ../linux-generic/odp_cpumask_task.c \
			   odp_crypto.c \
			   odp_errno.c \
			   ../linux-generic/odp_event.c \
			   ../linux-generic/odp_hash.c \
			   odp_init.c \
			   ../linux-generic/odp_impl.c \
			   ../linux-generic/odp_ipsec.c \
			   ../linux-generic/odp_ipsec_events.c \
			   ../linux-generic/odp_ipsec_sad.c \
			   ../linux-generic/odp_name_table.c \
			   ../linux-generic/odp_libconfig.c \
			   odp_packet.c \
			   odp_packet_dpdk.c \
			   odp_packet_flags.c \
			   ../linux-generic/odp_packet_io.c \
			   ../linux-generic/pktio/loop.c \
			   ../linux-generic/pktio/null.c \
			   ../linux-generic/odp_pkt_queue.c \
			   odp_pool.c \
			   odp_queue_basic.c \
			   odp_queue_eventdev.c \
			   odp_queue_if.c \
			   ../linux-generic/odp_queue_lf.c \
			   ../linux-generic/odp_random.c \
			   ../linux-generic/odp_rwlock.c \
			   ../linux-generic/odp_rwlock_recursive.c \
			   ../linux-generic/odp_schedule_basic.c \
			   odp_schedule_eventdev.c \
			   odp_schedule_if.c \
			   ../linux-generic/odp_schedule_sp.c \
			   ../linux-generic/odp_schedule_iquery.c \
			   odp_shared_memory.c \
			   ../linux-generic/odp_sorted_list.c \
			   ../linux-generic/odp_spinlock.c \
			   ../linux-generic/odp_spinlock_recursive.c \
			   ../linux-generic/odp_system_info.c \
			   ../linux-generic/odp_pcapng.c \
			   odp_thread.c \
			   ../linux-generic/odp_thrmask.c \
			   odp_time.c \
			   odp_timer.c \
			   ../linux-generic/odp_timer_wheel.c \
			   ../linux-generic/odp_traffic_mngr.c \
			   ../linux-generic/odp_version.c \
			   ../linux-generic/odp_weak.c

if ODP_ABI_COMPAT
__LIB__libodp_linux_la_SOURCES += \
			   ../linux-generic/odp_atomic_api.c \
			   ../linux-generic/odp_byteorder.c \
			   ../linux-generic/odp_event_api.c \
			   ../linux-generic/odp_packet_api.c \
			   ../linux-generic/odp_packet_flags_api.c \
			   ../linux-generic/odp_pktio_api.c \
			   odp_std_clib.c \
			   ../linux-generic/odp_sync.c \
			   ../linux-generic/odp_thread_api.c \
			   ../linux-generic/odp_ticketlock.c
endif

if ARCH_IS_ARM
__LIB__libodp_linux_la_SOURCES += arch/default/odp_cpu_cycles.c \
				 arch/default/odp_global_time.c \
				 arch/default/odp_sysinfo_parse.c
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/arm/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/arm/odp_atomic.h \
		  arch/arm/odp_cpu.h \
		  arch/arm/odp_cpu_idling.h \
		  arch/default/odp_cpu_idling.h \
		  arch/arm/odp_llsc.h
endif
if ARCH_IS_AARCH64
__LIB__libodp_linux_la_SOURCES += arch/default/odp_cpu_cycles.c \
				 arch/aarch64/odp_global_time.c \
				 arch/default/odp_sysinfo_parse.c
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/aarch64/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/aarch64/odp_atomic.h \
		  arch/aarch64/odp_cpu.h \
		  arch/aarch64/odp_cpu_idling.h \
		  arch/default/odp_cpu_idling.h \
		  arch/aarch64/odp_llsc.h
endif
if ARCH_IS_DEFAULT
__LIB__libodp_linux_la_SOURCES += arch/default/odp_cpu_cycles.c \
				 arch/default/odp_global_time.c \
				 arch/default/odp_sysinfo_parse.c
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/default/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/default/odp_cpu.h \
		  arch/default/odp_cpu_idling.h
endif
if ARCH_IS_MIPS64
__LIB__libodp_linux_la_SOURCES += arch/mips64/odp_cpu_cycles.c \
				 arch/default/odp_global_time.c \
				 arch/mips64/odp_sysinfo_parse.c
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/mips64/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/default/odp_cpu.h \
		  arch/default/odp_cpu_idling.h
endif
if ARCH_IS_POWERPC
__LIB__libodp_linux_la_SOURCES += arch/default/odp_cpu_cycles.c \
				 arch/default/odp_global_time.c \
				 arch/powerpc/odp_sysinfo_parse.c
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/powerpc/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/default/odp_cpu.h \
		  arch/default/odp_cpu_idling.h
endif
if ARCH_IS_X86
__LIB__libodp_linux_la_SOURCES += arch/x86/cpu_flags.c \
				 arch/x86/odp_cpu_cycles.c \
				 arch/x86/odp_global_time.c \
				 arch/x86/odp_sysinfo_parse.c
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/x86/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/x86/cpu_flags.h
noinst_HEADERS += arch/default/odp_cpu.h \
		  arch/default/odp_cpu_idling.h
endif

__LIB__libodp_linux_la_LIBADD = $(ATOMIC_LIBS)
__LIB__libodp_linux_la_LIBADD += $(OPENSSL_LIBS)
__LIB__libodp_linux_la_LIBADD += $(LIBCONFIG_LIBS)
__LIB__libodp_linux_la_LIBADD += $(DPDK_LIBS_LIBODP)
__LIB__libodp_linux_la_LIBADD += $(PTHREAD_LIBS)
__LIB__libodp_linux_la_LIBADD += $(TIMER_LIBS)
