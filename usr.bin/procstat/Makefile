# $FreeBSD$

PROG=	procstat
MAN=	procstat.1
SRCS=	procstat.c		\
	procstat_args.c		\
	procstat_basic.c	\
	procstat_bin.c		\
	procstat_cred.c		\
	procstat_files.c	\
	procstat_kstack.c	\
	procstat_sigs.c		\
	procstat_threads.c	\
	procstat_vm.c

LDADD+=	-lutil -lprocstat -lkvm
DPADD+=	${LIBUTIL}

.include <bsd.prog.mk>
