/*
 * Defines for synchronous PPP/Cisco link level subroutines.
 *
 * Copyright (C) 1994 Cronyx Ltd.
 * Author: Serge Vakulenko, <vak@zebub.msk.su>
 *
 * This software is distributed with NO WARRANTIES, not even the implied
 * warranties for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Authors grant any other persons or organisations permission to use
 * or modify this software as long as this message is kept with the software,
 * all derivative works or modified versions.
 *
 * Version 2.0, Fri Oct  6 20:39:21 MSK 1995
 */

#ifndef _NET_IF_HDLC_H_
#define _NET_IF_HDLC_H_ 1

struct slcp {
	u_short state;          /* state machine */
	u_long  magic;          /* local magic number */
	u_char  echoid;         /* id of last keepalive echo request */
	u_char  confid;         /* id of last configuration request */
};

struct sipcp {
	u_short state;          /* state machine */
	u_char  confid;         /* id of last configuration request */
};

struct schap {
	u_char  state;          /* opened/closed */
	u_char  admin;          /* admin mode chap/pap/off */
	u_char  mode;           /* negotiated mode */
	u_char  lastid;         /* id of last request */
	u_char  name [32];      /* system identification name */
	u_char  passwd [16];    /* secret password */
	u_char  challenge [16]; /* random challenge */
};

struct sdlci {                  /* Frame Relay params per DLCI */
	u_short dlci;           /* DLCI number, 16..1023 */
	u_char status;          /* PVC status, active/new/delete */
};

/* PVC status field. */
#define FR_DLCI_DELETE	0x04	/* PVC is deleted */
#define FR_DLCI_ACTIVE	0x02	/* PVC is operational */
#define FR_DLCI_NEW	0x08	/* PVC is new */

#define PP_MAXDLCI 16           /* max DLCIs per channel */

struct sppp {
	struct  ifnet pp_if;    /* network interface data */
	struct  ifqueue pp_fastq; /* fast output queue */
	struct  sppp *pp_next;  /* next interface in keepalive list */
	u_int   pp_flags;       /* use Cisco protocol instead of PPP */
	u_short pp_alivecnt;    /* keepalive packets counter */
	u_short pp_loopcnt;     /* loopback detection counter */
	u_long  pp_seq;         /* local sequence number */
	u_long  pp_rseq;        /* remote sequence number */
	struct slcp lcp;        /* LCP params */
	struct sipcp ipcp;      /* IPCP params */
	struct schap chap;      /* CHAP params */
	struct sdlci fr [PP_MAXDLCI]; /* Frame Relay params */
};

#define PP_KEEPALIVE    0x01    /* use keepalive protocol */
#define PP_CISCO        0x02    /* use Cisco protocol instead of PPP */
#define PP_TIMO         0x04    /* cp_timeout routine active */
#define PP_FR           0x08    /* use Frame Relay protocol instead of PPP */

#define PP_MTU          1500    /* max. transmit unit */

#define LCP_STATE_CLOSED        0       /* LCP state: closed (conf-req sent) */
#define LCP_STATE_ACK_RCVD      1       /* LCP state: conf-ack received */
#define LCP_STATE_ACK_SENT      2       /* LCP state: conf-ack sent */
#define LCP_STATE_OPENED        3       /* LCP state: opened */

#define IPCP_STATE_CLOSED       0       /* IPCP state: closed (conf-req sent) */
#define IPCP_STATE_ACK_RCVD     1       /* IPCP state: conf-ack received */
#define IPCP_STATE_ACK_SENT     2       /* IPCP state: conf-ack sent */
#define IPCP_STATE_OPENED       3       /* IPCP state: opened */

#define CHAP_STATE_CLOSED       0       /* CHAP state: closed, challenge sent */
#define CHAP_STATE_OPENED       1       /* CHAP state: opened, ack got */

#define CHAP_MODE_OFF           0       /* CHAP administratively off */
#define CHAP_MODE_PAP           1       /* use PAP */
#define CHAP_MODE_MD5           2       /* use CHAP-MD5/PAP */

#ifdef KERNEL
#ifdef SPPP_LOADABLE
#   define sppp_attach  (*sppp_attach_ptr)
#   define sppp_detach  (*sppp_detach_ptr)
#   define sppp_input   (*sppp_input_ptr)
#   define sppp_ioctl   (*sppp_ioctl_ptr)
#   define sppp_dequeue (*sppp_dequeue_ptr)
#   define sppp_isempty (*sppp_isempty_ptr)
#   define sppp_flush   (*sppp_flush_ptr)
#endif

void sppp_attach (struct ifnet *ifp);
void sppp_detach (struct ifnet *ifp);
void sppp_input (struct ifnet *ifp, struct mbuf *m);
int sppp_ioctl (struct ifnet *ifp, int cmd, void *data);
struct mbuf *sppp_dequeue (struct ifnet *ifp);
struct mbuf *sppp_pick (struct ifnet *ifp);
int sppp_isempty (struct ifnet *ifp);
void sppp_flush (struct ifnet *ifp);
#endif

#endif /* _NET_IF_HDLC_H_ */
