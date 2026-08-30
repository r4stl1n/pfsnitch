# Builds against the kernel sources for the RUNNING kernel; a module built
# for one FreeBSD version is not expected to load on another.
#
#   make && doas make load       # or: doas kldload ./mac_pfsnitch.ko
#
# Requires /usr/src matching the installed kernel.

KMOD=	mac_pfsnitch
SRCS=	mac_pfsnitch.c
# Generated headers the kernel headers we pull in expect to exist.
SRCS+=	vnode_if.h opt_inet.h opt_inet6.h opt_mac.h

.include <bsd.kmod.mk>
