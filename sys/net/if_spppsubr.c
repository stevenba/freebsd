/*
 * Synchronous PPP/Cisco/Frame Relay link level subroutines.
 * Keepalive protocol implemented in both Cisco and PPP modes.
 * ANSI T1.617-compaible link management signaling
 * implemented for Frame Relay mode.
 * Only one DLCI per channel for now.
 *
 * Copyright (C) 1994-1996 Cronyx Engineering Ltd.
 * Author: Serge Vakulenko, <vak@cronyx.ru>
 *
 * This software is distributed with NO WARRANTIES, not even the implied
 * warranties for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Authors grant any other persons or organisations permission to use
 * or modify this software as long as this message is kept with the software,
 * all derivative works or modified versions.
 *
 * Version 2.4, Thu Apr 30 17:17:21 MSD 1997
 */
#undef DEBUG

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#ifdef BSDI2
#include <machine/cpu.h>
#endif

#include <net/if.h>
#include <net/netisr.h>
#include <net/if_types.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#endif

#ifdef NS
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif

#ifdef ISO
#include <netiso/argo_debug.h>
#include <netiso/iso.h>
#include <netiso/iso_var.h>
#include <netiso/iso_snpac.h>
#endif

#if defined (SPPP_MODULE)
#   undef SPPP_LOADABLE
#endif

#include <net/if_sppp.h>

/*
 * In the case of dynamic SPPP driver loading
 * the only thing we need here is the declaration of (zero-valued)
 * function pointer; this is done in if_sppp.h.
 */
struct sppp *spppq;

#ifndef SPPP_LOADABLE

#ifdef DEBUG
#define print(s)        printf s
#else
#define print(s)        {/*void*/}
#endif

#define MAXALIVECNT     3               /* max. alive packets */

#define PPP_ALLSTATIONS 0xff            /* All-Stations broadcast address */
#define PPP_UI          0x03            /* Unnumbered Information */
#define PPP_IP          0x0021          /* Internet Protocol */
#define PPP_ISO         0x0023          /* ISO OSI Protocol */
#define PPP_XNS         0x0025          /* Xerox NS Protocol */
#define PPP_LCP         0xc021          /* Link Control Protocol */
#define PPP_PAP         0xc023          /* Password Authentication Protocol */
#define PPP_CHAP        0xc223          /* Challenge-Handshake Auth Protocol */
#define PPP_IPCP        0x8021          /* Internet Protocol Control Protocol */

#define LCP_CONF_REQ    1               /* PPP LCP configure request */
#define LCP_CONF_ACK    2               /* PPP LCP configure acknowledge */
#define LCP_CONF_NAK    3               /* PPP LCP configure negative ack */
#define LCP_CONF_REJ    4               /* PPP LCP configure reject */
#define LCP_TERM_REQ    5               /* PPP LCP terminate request */
#define LCP_TERM_ACK    6               /* PPP LCP terminate acknowledge */
#define LCP_CODE_REJ    7               /* PPP LCP code reject */
#define LCP_PROTO_REJ   8               /* PPP LCP protocol reject */
#define LCP_ECHO_REQ    9               /* PPP LCP echo request */
#define LCP_ECHO_REPLY  10              /* PPP LCP echo reply */
#define LCP_DISC_REQ    11              /* PPP LCP discard request */

#define LCP_OPT_MRU             1       /* maximum receive unit */
#define LCP_OPT_ASYNC_MAP       2       /* async control character map */
#define LCP_OPT_AUTH_PROTO      3       /* authentication protocol */
#define LCP_OPT_QUAL_PROTO      4       /* quality protocol */
#define LCP_OPT_MAGIC           5       /* magic number */
#define LCP_OPT_RESERVED        6       /* reserved */
#define LCP_OPT_PROTO_COMP      7       /* protocol field compression */
#define LCP_OPT_ADDR_COMP       8       /* address/control field compression */

#define IPCP_CONF_REQ   LCP_CONF_REQ    /* PPP IPCP configure request */
#define IPCP_CONF_ACK   LCP_CONF_ACK    /* PPP IPCP configure acknowledge */
#define IPCP_CONF_NAK   LCP_CONF_NAK    /* PPP IPCP configure negative ack */
#define IPCP_CONF_REJ   LCP_CONF_REJ    /* PPP IPCP configure reject */
#define IPCP_TERM_REQ   LCP_TERM_REQ    /* PPP IPCP terminate request */
#define IPCP_TERM_ACK   LCP_TERM_ACK    /* PPP IPCP terminate acknowledge */
#define IPCP_CODE_REJ   LCP_CODE_REJ    /* PPP IPCP code reject */

#define IPCP_OPT_COMPRESSION	2	/* IP compression protocol option */
#define IPCP_OPT_ADDRESS	3	/* IP address option */

#define PAP_REQUEST             1       /* PAP name/password request */
#define PAP_ACK                 2       /* PAP acknowledge */
#define PAP_NACK                3       /* PAP fail */

#define CHAP_CHALLENGE          1       /* CHAP challenge request */
#define CHAP_RESPONSE           2       /* CHAP challenge response */
#define CHAP_SUCCESS            3       /* CHAP response ok */
#define CHAP_FAILURE            4       /* CHAP response failed */

#define CHAP_MD5                5       /* hash algorithm - MD5 */

#define CISCO_MULTICAST         0x8f    /* Cisco multicast address */
#define CISCO_UNICAST           0x0f    /* Cisco unicast address */
#define CISCO_KEEPALIVE         0x8035  /* Cisco keepalive protocol */
#define CISCO_ADDR_REQ          0       /* Cisco address request */
#define CISCO_ADDR_REPLY        1       /* Cisco address reply */
#define CISCO_KEEPALIVE_REQ     2       /* Cisco keepalive request */

struct ppp_header {
	u_char address;
	u_char control;
	u_short protocol;
};
#define PPP_HEADER_LEN          sizeof (struct ppp_header)

struct lcp_header {
	u_char type;
	u_char ident;
	u_short len;
};
#define LCP_HEADER_LEN          sizeof (struct lcp_header)

struct cisco_packet {
	u_long type;
	u_long par1;
	u_long par2;
	u_short rel;
	u_short time0;
	u_short time1;
};
#define CISCO_PACKET_LEN 18

/*
 * Frame Relay.
 */
#define FR_IP           0xCC    /* IP protocol identifier */
#define FR_PADDING      0x00    /* NLPID padding */
#define FR_SIGNALING    0x08    /* Q.933/T1.617 signaling identifier */
#define FR_SNAP         0x80    /* NLPID snap */

/*
 * Header flags.
 */
#define FR_DE           0x02    /* discard eligibility */
#define FR_FECN         0x04    /* forward notification */
#define FR_BECN         0x08    /* backward notification */

/*
 * Signaling message types.
 */
#define FR_MSG_ENQUIRY  0x75    /* status enquiry */
#define FR_MSG_STATUS   0x7d    /* status */

/*
 * Message field types.
 */
#define FR_FLD_RTYPE    0x01    /* report type */
#define FR_FLD_VERIFY   0x03    /* link verification */
#define FR_FLD_PVC      0x07    /* PVC status */
#define FR_FLD_LSHIFT5  0x95    /* locking shift 5 */

/*
 * Report types.
 */
#define FR_RTYPE_FULL   0       /* full status */
#define FR_RTYPE_SHORT  1       /* link verification only */
#define FR_RTYPE_SINGLE 2       /* single PVC status */

#define STATUS_ENQUIRY_SIZE 14

struct arp_req {
	unsigned short  htype;          /* hardware type = ARPHRD_FRELAY */
	unsigned short  ptype;          /* protocol type = ETHERTYPE_IP */
	unsigned char   halen;          /* hardware address length = 2 */
	unsigned char   palen;          /* protocol address length = 4 */
	unsigned short  op;             /* ARP/RARP/InARP request/reply */
	unsigned short  hsource;        /* hardware source address */
	unsigned short  psource1;       /* protocol source */
	unsigned short  psource2;
	unsigned short  htarget;        /* hardware target address */
	unsigned short  ptarget1;       /* protocol target */
	unsigned short  ptarget2;
};

/* MD5 context. */
typedef struct {
	unsigned long state[4];       /* state (ABCD) */
	unsigned long count[2];       /* N of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];     /* input buffer */
} MD5_CTX;
static void MD5Init (MD5_CTX*);
static void MD5Update (MD5_CTX*, const unsigned char*, unsigned int);
static void MD5Final (unsigned char [16], MD5_CTX*);

/*
 * The following disgusting hack gets around the problem that IP TOS
 * can't be set yet.  We want to put "interactive" traffic on a high
 * priority queue.  To decide if traffic is interactive, we check that
 * a) it is TCP and b) one of its ports is telnet, rlogin or ftp control.
 */
static u_short interactive_ports[8] = {
	0,	513,	0,	0,
	0,	21,	0,	23,
};
#define INTERACTIVE(p) (interactive_ports[(p) & 7] == (p))

/*
 * Timeout routine activation macros.
 */
#define TIMO(p,s) if (! ((p)->pp_flags & PP_TIMO)) { \
			timeout (sppp_cp_timeout, (void*) (p), (s)*hz); \
			(p)->pp_flags |= PP_TIMO; }
#define UNTIMO(p) if ((p)->pp_flags & PP_TIMO) { \
			untimeout (sppp_cp_timeout, (void*) (p)); \
			(p)->pp_flags &= ~PP_TIMO; }

void sppp_keepalive (void *dummy);
void sppp_cp_send (struct sppp *sp, u_short proto, u_char type,
	u_char ident, u_short len, void *data);
void sppp_cisco_send (struct sppp *sp, int type, long par1, long par2);
void sppp_lcp_input (struct sppp *sp, struct mbuf *m);
void sppp_cisco_input (struct sppp *sp, struct mbuf *m);
void sppp_ipcp_input (struct sppp *sp, struct mbuf *m);
void sppp_pap_input (struct sppp *sp, struct mbuf *m);
void sppp_chap_input (struct sppp *sp, struct mbuf *m);
void sppp_lcp_open (struct sppp *sp);
void sppp_ipcp_open (struct sppp *sp);
void sppp_chap_open (struct sppp *sp);
int sppp_lcp_conf_parse_options (struct sppp *sp, struct lcp_header *h,
	int len, u_long *magic);
void sppp_lcp_rej_parse_options (struct sppp *sp, struct lcp_header *h,
	int len);
int sppp_ipcp_conf_parse_options (struct sppp *sp, struct lcp_header *h,
	int len);
void sppp_cp_timeout (void *arg);
char *sppp_lcp_type_name (u_char type);
char *sppp_ipcp_type_name (u_char type);
void sppp_print_bytes (u_char *p, u_short len);
static void sppp_fr_signal (struct sppp *sp, unsigned char *h, int len);
static void sppp_fr_arp (struct sppp *sp, struct arp_req *req,
	u_short his_hardware_address);

static void prbytes (unsigned char *p, int len)
{
	printf ("%02x", *p++);
	while (--len > 0)
		printf ("-%02x", *p++);
	printf ("\n");
}

/*
 * Flush interface queue.
 */
static void qflush (struct ifqueue *ifq)
{
	struct mbuf *m, *n;

	n = ifq->ifq_head;
	while ((m = n)) {
		n = m->m_act;
		m_freem (m);
	}
	ifq->ifq_head = 0;
	ifq->ifq_tail = 0;
	ifq->ifq_len = 0;
}

static int strnlen (u_char *p, int max)
{
	int len;

	for (len=0; len<max && *p; ++p)
		++len;
	return len;
}

static int equal (u_char *a, u_char *b, int len)
{
	while (len-- > 0)
		if (*a++ != *b++)
			return 0;
	return 1;
}

static struct ifaddr *myifaddr (struct ifnet *ifp)
{
	struct ifaddr *ifa;

	for (ifa=ifp->if_addrlist; ifa; ifa=ifa->ifa_next)
		if (ifa->ifa_addr->sa_family == AF_INET)
			break;
	if (! ifa) {
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: unknown IP address\n",
				ifp->if_name, ifp->if_unit);
		return 0;
	}
	return ifa;
}

static struct mbuf *sppp_switch_ppp (struct sppp *sp, struct mbuf *m,
	struct ifqueue **inq)
{
	struct ifnet *ifp = &sp->pp_if;
	struct ppp_header *h = mtod (m, struct ppp_header*);

	/* Remove PPP header. */
	m_adj (m, PPP_HEADER_LEN);

	*inq = 0;
	switch (h->address) {
	default:        /* Invalid PPP packet. */
invalid:        if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: invalid input packet <0x%x 0x%x 0x%x>\n",
				ifp->if_name, ifp->if_unit,
				h->address, h->control, ntohs (h->protocol));
		return m;
	case PPP_ALLSTATIONS:
		if (h->control != PPP_UI)
			goto invalid;
		if (sp->pp_flags & PP_CISCO) {
			if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: PPP packet in Cisco mode <0x%x 0x%x 0x%x>\n",
					ifp->if_name, ifp->if_unit,
					h->address, h->control, ntohs (h->protocol));
			return m;
		}
		switch (ntohs (h->protocol)) {
		default:
			if (sp->lcp.state == LCP_STATE_OPENED)
				sppp_cp_send (sp, PPP_LCP, LCP_PROTO_REJ,
					++sp->pp_seq, m->m_pkthdr.len + 2,
					&h->protocol);
			if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: invalid input protocol <0x%x 0x%x 0x%x>\n",
					ifp->if_name, ifp->if_unit,
					h->address, h->control, ntohs (h->protocol));
			++ifp->if_noproto;
			return m;
		case PPP_LCP:
			sppp_lcp_input (sp, m);
			m_freem (m);
			return 0;
		case PPP_PAP:
			sppp_pap_input (sp, m);
			m_freem (m);
			return 0;
		case PPP_CHAP:
			sppp_chap_input (sp, m);
			m_freem (m);
			return 0;
#ifdef INET
		case PPP_IPCP:
			if (sp->lcp.state == LCP_STATE_OPENED &&
			    sp->chap.state == CHAP_STATE_OPENED)
				sppp_ipcp_input (sp, m);
			m_freem (m);
			return 0;
		case PPP_IP:
			if (sp->ipcp.state == IPCP_STATE_OPENED) {
				schednetisr (NETISR_IP);
				*inq = &ipintrq;
			}
			break;
#endif
#ifdef NS
		case PPP_XNS:
			/* XNS IDPCP not implemented yet */
			if (sp->lcp.state == LCP_STATE_OPENED &&
			    sp->chap.state == CHAP_STATE_OPENED) {
				schednetisr (NETISR_NS);
				*inq = &nsintrq;
			}
			break;
#endif
#ifdef ISO
		case PPP_ISO:
			/* OSI NLCP not implemented yet */
			if (sp->lcp.state == LCP_STATE_OPENED &&
			    sp->chap.state == CHAP_STATE_OPENED) {
				schednetisr (NETISR_ISO);
				*inq = &clnlintrq;
			}
			break;
#endif
		}
		break;
	case CISCO_MULTICAST:
	case CISCO_UNICAST:
		/* Don't check the control field here (RFC 1547). */
		if (! (sp->pp_flags & PP_CISCO)) {
			if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: Cisco packet in PPP mode <0x%x 0x%x 0x%x>\n",
					ifp->if_name, ifp->if_unit,
					h->address, h->control, ntohs (h->protocol));
			return m;
		}
		switch (ntohs (h->protocol)) {
		default:
			++ifp->if_noproto;
			goto invalid;
		case CISCO_KEEPALIVE:
			sppp_cisco_input (sp, m);
			m_freem (m);
			return 0;
#ifdef INET
		case ETHERTYPE_IP:
			schednetisr (NETISR_IP);
			*inq = &ipintrq;
			break;
#endif
#ifdef NS
		case ETHERTYPE_NS:
			schednetisr (NETISR_NS);
			*inq = &nsintrq;
			break;
#endif
		}
		break;
	}
	return m;
}

static struct mbuf *sppp_switch_fr (struct sppp *sp, struct mbuf *m,
	struct ifqueue **inq)
{
	struct ifnet *ifp = &sp->pp_if;
	u_char *h = mtod (m, u_char*);
	int dlci, hlen, proto, i;

	/* Get the DLCI number. */
	if (m->m_pkthdr.len < 10) {
bad:            m_freem (m);
		return 0;
	}
	dlci = (h[0] << 2 & 0x3f0) | (h[1] >> 4 & 0x0f);

	/* Process signaling packets. */
	*inq = 0;
	if (dlci == 0) {
		sppp_fr_signal (sp, h, m->m_pkthdr.len);
		m_freem (m);
		return 0;
	}

	for (i=0; i<PP_MAXDLCI; ++i)
		if (dlci == sp->fr[i].dlci)
			break;

	if (i >= PP_MAXDLCI) {
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: Received packet from invalid DLCI %i\n",
				ifp->if_name, ifp->if_unit, dlci);
		goto bad;
	}

	/* Process the packet. */
	if (h[2] != PPP_UI) {
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: Invalid frame relay header flag 0x%02x\n",
				ifp->if_name, ifp->if_unit, h[2]);
		goto bad;
	}
	switch (h[3]) {
	default:
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: Unsupported NLPID 0x%02x\n",
				ifp->if_name, ifp->if_unit, h[3]);
		goto bad;

	case FR_PADDING:
		if (h[4] != FR_SNAP) {
			if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: Bad NLPID 0x%02x\n",
					ifp->if_name, ifp->if_unit, h[4]);
			goto bad;
		}
		if (h[5] || h[6] || h[7]) {
			if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: Bad OID 0x%02x-0x%02x-0x%02x\n",
					ifp->if_name, ifp->if_unit,
					h[5], h[6], h[7]);
			goto bad;
		}
		proto = ntohs (*(short*) (h+8));
		if (proto == ETHERTYPE_ARP) {
			/* Process the ARP request. */
			if (m->m_pkthdr.len != 10 + sizeof (struct arp_req)) {
				if (ifp->if_flags & IFF_DEBUG)
					printf ("%s%d: Bad ARP request size = %d bytes\n",
						ifp->if_name, ifp->if_unit,
						m->m_pkthdr.len);
				goto bad;
			}
			sppp_fr_arp (sp, (struct arp_req*) (h + 10),
				h[0] << 8 | h[1]);
			m_freem (m);
			return 0;
		}
		hlen = 10;
		break;

	case FR_IP:
		proto = ETHERTYPE_IP;
		hlen = 4;
		break;
	}

	/* Remove frame relay header. */
	m_adj (m, hlen);

	switch (proto) {
	default:
		++ifp->if_noproto;
		return m;
#ifdef INET
	case ETHERTYPE_IP:
		schednetisr (NETISR_IP);
		*inq = &ipintrq;
		break;
#endif
#ifdef IPX
	case ETHERTYPE_IPX:
		schednetisr (NETISR_IPX);
		*inq = &ipxintrq;
		break;
#endif
#ifdef NS
	case 0x8137: /* Novell Ethernet_II Ethernet TYPE II */
		schednetisr (NETISR_NS);
		*inq = &nsintrq;
		break;
#endif
#ifdef NETATALK
        case ETHERTYPE_AT:
		schednetisr (NETISR_ATALK);
		*inq = &atintrq1;
                break;
#endif
	}
	return m;
}

/*
 * Process the received packet.
 */
void sppp_input (struct ifnet *ifp, struct mbuf *m)
{
	struct sppp *sp = (struct sppp*) ifp;
	struct ifqueue *inq = 0;
	int s;

	ifp->if_lastchange = time;
	if (ifp->if_flags & IFF_UP)
		/* Count received bytes, add FCS and one flag */
		ifp->if_ibytes += m->m_pkthdr.len + 3;

	if (m->m_pkthdr.len <= PPP_HEADER_LEN) {
		/* Too small packet, drop it. */
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: input packet is too small, %d bytes\n",
				ifp->if_name, ifp->if_unit, m->m_pkthdr.len);
drop:           ++ifp->if_iqdrops;
		m_freem (m);
		return;
	}

	if (sp->pp_flags & PP_FR)
		m = sppp_switch_fr (sp, m, &inq);
	else
		m = sppp_switch_ppp (sp, m, &inq);
	if (! m)
		return;

	if (! (ifp->if_flags & IFF_UP) || ! inq)
		goto drop;

	/* Check queue. */
	s = splimp ();
	if (IF_QFULL (inq)) {
		/* Queue overflow. */
		IF_DROP (inq);
		splx (s);
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: protocol queue overflow\n",
				ifp->if_name, ifp->if_unit);
		goto drop;
	}
	IF_ENQUEUE (inq, m);
	splx (s);
}

/*
 * Add the frame relay header to the packet.
 * For IP the header length is 4 bytes,
 * for all other protocols - 10 bytes (RFC 1490).
 */
static struct mbuf *sppp_fr_header (struct sppp *sp, struct mbuf *m,
	int family)
{
	struct ifnet *ifp = &sp->pp_if;
	u_char *h;
	int type, hlen;

	/* Prepend the space for Frame Relay header. */
	hlen = (family == AF_INET) ? 4 : 10;
	M_PREPEND (m, hlen, M_DONTWAIT);
	if (! m)
		return 0;
	h = mtod (m, u_char*);

	/* Fill the header. */
	h[0] = sp->fr[0].dlci >> 2 & 0xfc;
	h[1] = sp->fr[0].dlci << 4 | 1;
	h[2] = PPP_UI;

	switch (family) {
	default:
		printf ("%s%d: Cannot handle address family %d\n",
			ifp->if_name, ifp->if_unit, family);
		m_freem (m);
		return 0;
#ifdef INET
	case AF_INET:
		/*
		 * Set the discard eligibility bit, if:
		 * 1) no fragmentation
		 * 2) length > 400 bytes
		 * 3a) the protocol is UDP or
		 * 3b) TCP data (no control bits)
		 */
		{
		struct ip *ip = (struct ip*) (h + hlen);
		struct tcphdr *tcp = (struct tcphdr*) ((long*)ip + ip->ip_hl);

		if (! (ip->ip_off & ~IP_DF) && ip->ip_len > 400 &&
		    (ip->ip_p == IPPROTO_UDP ||
		    ip->ip_p == IPPROTO_TCP && ! tcp->th_flags))
			h[1] |= FR_DE;
		}
		h[3] = FR_IP;
		return m;
#endif
#ifdef IPX
	case AF_IPX:
		type = ETHERTYPE_IPX;
		break;
#endif
#ifdef NS
	case AF_NS:
		type = 0x8137;
		break;
#endif
#ifdef NETATALK
	case AF_APPLETALK:
		type = ETHERTYPE_AT;
		break;
#endif
	}
	h[3] = FR_PADDING;
	h[4] = FR_SNAP;
	h[5] = 0;
	h[6] = 0;
	h[7] = 0;
	*(short*) (h+8) = htons(type);
	return m;
}

/*
 * Enqueue transmit packet.
 */
static int sppp_output (struct ifnet *ifp, struct mbuf *m,
	struct sockaddr *dst, struct rtentry *rt)
{
	struct sppp *sp = (struct sppp*) ifp;
	struct ppp_header *h;
	struct ifqueue *ifq;
	int s = splimp ();

	if (! (ifp->if_flags & IFF_UP) || ! (ifp->if_flags & IFF_RUNNING)) {
		m_freem (m);
		splx (s);
		return (ENETDOWN);
	}

	ifq = &ifp->if_snd;
#ifdef INET
	/*
	 * Put low delay, telnet, rlogin and ftp control packets
	 * in front of the queue.
	 */
	{
	struct ip *ip = mtod (m, struct ip*);
	struct tcphdr *tcp = (struct tcphdr*) ((long*)ip + ip->ip_hl);

	if (! IF_QFULL (&sp->pp_fastq) && ((ip->ip_tos & IPTOS_LOWDELAY) ||
	    ip->ip_p == IPPROTO_TCP &&
	    m->m_len >= sizeof (struct ip) + sizeof (struct tcphdr) &&
	    (INTERACTIVE (ntohs (tcp->th_sport)) ||
	    INTERACTIVE (ntohs (tcp->th_dport)))))
		ifq = &sp->pp_fastq;
	}
#endif

	if (dst->sa_family == AF_UNSPEC) /* for raw interface via bpfilter */
		goto out;

	if (sp->pp_flags & PP_FR) {
		/* Add frame relay header. */
		m = sppp_fr_header (sp, m, dst->sa_family);
		if (! m)
			goto nobufs;
		goto out;
	}

	/*
	 * Prepend general data packet PPP header. For now, IP only.
	 */
	M_PREPEND (m, PPP_HEADER_LEN, M_DONTWAIT);
	if (! m) {
nobufs:         if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: no memory for transmit header\n",
				ifp->if_name, ifp->if_unit);
		splx (s);
		return (ENOBUFS);
	}
	h = mtod (m, struct ppp_header*);
	if (sp->pp_flags & PP_CISCO) {
		h->address = CISCO_MULTICAST;        /* broadcast address */
		h->control = 0;
	} else {
		h->address = PPP_ALLSTATIONS;        /* broadcast address */
		h->control = PPP_UI;                 /* Unnumbered Info */
	}

	switch (dst->sa_family) {
#ifdef INET
	case AF_INET:   /* Internet Protocol */
		if (sp->pp_flags & PP_CISCO)
			h->protocol = htons (ETHERTYPE_IP);
		else if (sp->ipcp.state == IPCP_STATE_OPENED)
			h->protocol = htons (PPP_IP);
		else {
			m_freem (m);
			splx (s);
			return (ENETDOWN);
		}
		break;
#endif
#ifdef NS
	case AF_NS:     /* Xerox NS Protocol */
		h->protocol = htons ((sp->pp_flags & PP_CISCO) ?
			ETHERTYPE_NS : PPP_XNS);
		break;
#endif
#ifdef ISO
	case AF_ISO:    /* ISO OSI Protocol */
		if (sp->pp_flags & PP_CISCO)
			goto nosupport;
		h->protocol = htons (PPP_ISO);
		break;
nosupport:
#endif
	default:
		m_freem (m);
		splx (s);
		return (EAFNOSUPPORT);
	}
out:
	/*
	 * Queue message on interface, and start output if interface
	 * not yet active.
	 */
	if (IF_QFULL (ifq)) {
		IF_DROP (&ifp->if_snd);
		m_freem (m);
		splx (s);
		return (ENOBUFS);
	}
	IF_ENQUEUE (ifq, m);
	if (! (ifp->if_flags & IFF_OACTIVE))
		(*ifp->if_start) (ifp);

	/*
	 * Count output packets and bytes.
	 * The packet length includes header, FCS and 1 flag,
	 * according to RFC 1333.
	 */
	ifp->if_obytes += m->m_pkthdr.len + 3;
	ifp->if_lastchange = time;
	splx (s);
	return (0);
}

void sppp_attach (struct ifnet *ifp)
{
	struct sppp *sp = (struct sppp*) ifp;

	/* Initialize keepalive handler. */
	if (! spppq)
		timeout (sppp_keepalive, 0, hz * 10);

	/* Insert new entry into the keepalive list. */
	sp->pp_next = spppq;
	spppq = sp;

	sp->pp_if.if_type = IFT_PPP;
	sp->pp_if.if_output = sppp_output;
	sp->pp_fastq.ifq_maxlen = 32;
	sp->pp_loopcnt = 0;
	sp->pp_alivecnt = 0;
	sp->pp_seq = 0;
	sp->pp_rseq = 0;
	sp->lcp.magic = 0;
	sp->lcp.state = LCP_STATE_CLOSED;
	sp->ipcp.state = IPCP_STATE_CLOSED;
	sp->chap.state = CHAP_STATE_CLOSED;
	sp->chap.mode = sp->chap.admin;
}

void sppp_detach (struct ifnet *ifp)
{
	struct sppp **q, *p, *sp = (struct sppp*) ifp;

	/* Remove the entry from the keepalive list. */
	for (q = &spppq; (p = *q); q = &p->pp_next)
		if (p == sp) {
			*q = p->pp_next;
			break;
		}

	/* Stop keepalive handler. */
	if (! spppq)
		untimeout (sppp_keepalive, 0);
	UNTIMO (sp);
}

/*
 * Flush the interface output queue.
 */
void sppp_flush (struct ifnet *ifp)
{
	struct sppp *sp = (struct sppp*) ifp;

	qflush (&sp->pp_if.if_snd);
	qflush (&sp->pp_fastq);
}

/*
 * Check if the output queue is empty.
 */
int sppp_isempty (struct ifnet *ifp)
{
	struct sppp *sp = (struct sppp*) ifp;
	int empty, s = splimp ();

	empty = !sp->pp_fastq.ifq_head && !sp->pp_if.if_snd.ifq_head;
	splx (s);
	return (empty);
}

/*
 * Get next packet to send.
 */
struct mbuf *sppp_dequeue (struct ifnet *ifp)
{
	struct sppp *sp = (struct sppp*) ifp;
	struct mbuf *m;
	int s = splimp ();

	IF_DEQUEUE (&sp->pp_fastq, m);
	if (! m)
		IF_DEQUEUE (&sp->pp_if.if_snd, m);
	splx (s);
	return (m);
}

/*
 * Pick the next packet, do not remove it from the queue.
 */
struct mbuf *sppp_pick (struct ifnet *ifp)
{
	struct sppp *sp = (struct sppp*) ifp;
	struct mbuf *m;
	int s = splimp ();

	m = sp->pp_fastq.ifq_head;
	if (! m)
		m = sp->pp_if.if_snd.ifq_head;
	splx (s);
	return (m);
}

/*
 * Send periodical frame relay link verification messages via DLCI 0.
 * Called every 10 seconds (default value of T391 timer is 10 sec).
 * Every 6-th message is a full status request
 * (default value of N391 counter is 6).
 */
static void sppp_fr_keepalive (struct sppp *sp)
{
	struct ifnet *ifp = &sp->pp_if;
	unsigned char *h, *p;
	struct mbuf *m;

	MGETHDR (m, M_DONTWAIT, MT_DATA);
	if (! m)
		return;
	m->m_pkthdr.rcvif = 0;

	h = mtod (m, u_char*);
	p = h;
	*p++ = 0;                       /* DLCI = 0 */
	*p++ = 1;
	*p++ = PPP_UI;
	*p++ = FR_SIGNALING;            /* NLPID = UNI call control */

	*p++ = 0;                       /* call reference length = 0 */
	*p++ = FR_MSG_ENQUIRY;          /* message type = status enquiry */

	*p++ = FR_FLD_LSHIFT5;          /* locking shift 5 */

	*p++ = FR_FLD_RTYPE;            /* report type field */
	*p++ = 1;                       /* report type length = 1 */
	if (sp->pp_seq % 6)
		*p++ = FR_RTYPE_SHORT;  /* link verification only */
	else
		*p++ = FR_RTYPE_FULL;   /* full status needed */

	*p++ = FR_FLD_VERIFY;           /* link verification type field */
	*p++ = 2;                       /* link verification field length = 2 */
	*p++ = ++sp->pp_seq;            /* our sequence number */
	*p++ = sp->pp_rseq;             /* last received sequence number */

	m->m_pkthdr.len = m->m_len = p - h;
	if (ifp->if_flags & IFF_DEBUG)
		printf ("%s%d: send lmi packet, seq=%d, rseq=%d\n",
			ifp->if_name, ifp->if_unit, (u_char) sp->pp_seq,
			(u_char) sp->pp_rseq);

	if (IF_QFULL (&sp->pp_fastq)) {
		IF_DROP (&ifp->if_snd);
		m_freem (m);
	} else
		IF_ENQUEUE (&sp->pp_fastq, m);
	if (! (ifp->if_flags & IFF_OACTIVE))
		(*ifp->if_start) (ifp);
	ifp->if_obytes += m->m_pkthdr.len + 3;
}

/*
 * Send keepalive packets, every 10 seconds.
 */
void sppp_keepalive (void *dummy)
{
	struct sppp *sp;
	int s = splimp ();

	for (sp=spppq; sp; sp=sp->pp_next) {
		struct ifnet *ifp = &sp->pp_if;

		/* Channel is down? */
		if (! (ifp->if_flags & IFF_RUNNING))
			continue;

		/* In cisco and frame relay modes the keepalive
		 * is always enabled.
		 * No keepalive in PPP mode if LCP not opened yet. */
		if (sp->pp_flags & PP_FR) {
			sppp_fr_keepalive (sp);
			continue;
		}

		if (! (sp->pp_flags & PP_CISCO) &&
		    (! (sp->pp_flags & PP_KEEPALIVE) ||
		    sp->lcp.state != LCP_STATE_OPENED))
			continue;

		if (sp->pp_alivecnt == MAXALIVECNT) {
			/* No keepalive packets got.  Stop the interface. */
			printf ("%s%d: down\n", ifp->if_name, ifp->if_unit);
			if_down (ifp);
			qflush (&sp->pp_fastq);
			if (! (sp->pp_flags & PP_CISCO)) {
				/* Shut down the PPP link. */
				sp->lcp.state = LCP_STATE_CLOSED;
				sp->ipcp.state = IPCP_STATE_CLOSED;
				sp->chap.state = CHAP_STATE_CLOSED;
				UNTIMO (sp);
				/* Initiate negotiation. */
				sppp_lcp_open (sp);
			}
		}
		if (sp->pp_alivecnt <= MAXALIVECNT)
			++sp->pp_alivecnt;
		if (sp->pp_flags & PP_CISCO)
			sppp_cisco_send (sp, CISCO_KEEPALIVE_REQ, ++sp->pp_seq,
				sp->pp_rseq);
		else if (sp->lcp.state == LCP_STATE_OPENED) {
			long nmagic = htonl (sp->lcp.magic);
			sp->lcp.echoid = ++sp->pp_seq;
			sppp_cp_send (sp, PPP_LCP, LCP_ECHO_REQ,
				sp->lcp.echoid, 4, &nmagic);
		}
	}
	splx (s);
	timeout (sppp_keepalive, 0, hz * 10);
}

static char sppp_state_name (int state)
{
	if (state<0 || state>3)
		return '?';
	return "CRSO" [state];
}

/*
 * Handle incoming PPP Link Control Protocol packets.
 */
void sppp_lcp_input (struct sppp *sp, struct mbuf *m)
{
	struct lcp_header *h;
	struct ifnet *ifp = &sp->pp_if;
	int len = m->m_pkthdr.len;
	u_char *p, opt[6];
	u_long rmagic;

	if (len < 4) {
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: invalid lcp packet length: %d bytes\n",
				ifp->if_name, ifp->if_unit, len);
		return;
	}
	h = mtod (m, struct lcp_header*);
	if (ifp->if_flags & IFF_DEBUG) {
		printf ("%s%d: lcp input(%c): %d bytes <%s id=%xh len=%xh",
			ifp->if_name, ifp->if_unit,
			sppp_state_name (sp->lcp.state), len,
			sppp_lcp_type_name (h->type), h->ident, ntohs (h->len));
		if (len > 4)
			sppp_print_bytes ((u_char*) (h+1), len-4);
		printf (">\n");
	}
	if (len > ntohs (h->len))
		len = ntohs (h->len);
	switch (h->type) {
	default:
		/* Unknown packet type -- send Code-Reject packet. */
		sppp_cp_send (sp, PPP_LCP, LCP_CODE_REJ, ++sp->pp_seq,
			m->m_pkthdr.len, h);
		break;
	case LCP_CONF_REQ:
		if (len < 4) {
			if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: invalid lcp configure request packet length: %d bytes\n",
					ifp->if_name, ifp->if_unit, len);
			break;
		}
		if (len>4 && !sppp_lcp_conf_parse_options (sp, h, len, &rmagic))
			goto badreq;
		if (rmagic == sp->lcp.magic) {
			/* Local and remote magics equal -- loopback? */
			if (sp->pp_loopcnt >= MAXALIVECNT*5) {
				printf ("%s%d: loopback\n",
					ifp->if_name, ifp->if_unit);
				sp->pp_loopcnt = 0;
				if (ifp->if_flags & IFF_UP) {
					if_down (ifp);
					qflush (&sp->pp_fastq);
				}
			} else if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: conf req: magic glitch\n",
					ifp->if_name, ifp->if_unit);
			++sp->pp_loopcnt;

			/* MUST send Conf-Nack packet. */
			rmagic = ~sp->lcp.magic;
			opt[0] = LCP_OPT_MAGIC;
			opt[1] = sizeof (opt);
			opt[2] = rmagic >> 24;
			opt[3] = rmagic >> 16;
			opt[4] = rmagic >> 8;
			opt[5] = rmagic;
			sppp_cp_send (sp, PPP_LCP, LCP_CONF_NAK,
				h->ident, sizeof (opt), &opt);
badreq:
			switch (sp->lcp.state) {
			case LCP_STATE_OPENED:
				/* Initiate renegotiation. */
				sppp_lcp_open (sp);
				/* fall through... */
			case LCP_STATE_ACK_SENT:
				/* Go to closed state. */
				sp->lcp.state = LCP_STATE_CLOSED;
				sp->ipcp.state = IPCP_STATE_CLOSED;
				sp->chap.state = CHAP_STATE_CLOSED;
			}
			break;
		}
		/* Send Configure-Ack packet. */
		sp->pp_loopcnt = 0;
		sppp_cp_send (sp, PPP_LCP, LCP_CONF_ACK,
			h->ident, len-4, h+1);
		/* Change the state. */
		switch (sp->lcp.state) {
		case LCP_STATE_CLOSED:
			sp->lcp.state = LCP_STATE_ACK_SENT;
			break;
		case LCP_STATE_ACK_RCVD:
			sp->lcp.state = LCP_STATE_OPENED;
			/* Time to authenticate.
			 * Let the peer be the first.
			 * chap_open() will be called by timer handler routine.
			 */
			TIMO (sp, 5);
			break;
		case LCP_STATE_OPENED:
			/* Remote magic changed -- close session. */
			sp->lcp.state = LCP_STATE_ACK_SENT;
			sp->ipcp.state = IPCP_STATE_CLOSED;
			sp->chap.state = CHAP_STATE_CLOSED;
			/* Initiate renegotiation. */
			sppp_lcp_open (sp);
			break;
		}
		break;
	case LCP_CONF_ACK:
		if (h->ident != sp->lcp.confid)
			break;
		UNTIMO (sp);
		if (! (ifp->if_flags & IFF_UP) &&
		    (ifp->if_flags & IFF_RUNNING)) {
			/* Coming out of loopback mode. */
			ifp->if_flags |= IFF_UP;
			printf ("%s%d: up\n", ifp->if_name, ifp->if_unit);
		}
		switch (sp->lcp.state) {
		case LCP_STATE_CLOSED:
			sp->lcp.state = LCP_STATE_ACK_RCVD;
			TIMO (sp, 5);
			break;
		case LCP_STATE_ACK_SENT:
			sp->lcp.state = LCP_STATE_OPENED;
			/* Time to authenticate.
			 * Let the peer be the first.
			 * chap_open() will be called by timer handler routine.
			 */
			TIMO (sp, 5);
			break;
		}
		break;
	case LCP_CONF_NAK:
		if (h->ident != sp->lcp.confid)
			break;
		p = (u_char*) (h+1);
		if (len>=10 && p[0] == LCP_OPT_MAGIC && p[1] >= 4) {
			rmagic = (u_long)p[2] << 24 |
				(u_long)p[3] << 16 | p[4] << 8 | p[5];
			if (rmagic == ~sp->lcp.magic) {
				if (ifp->if_flags & IFF_DEBUG)
					printf ("%s%d: conf nak: magic glitch\n",
						ifp->if_name, ifp->if_unit);
				sp->lcp.magic += time.tv_sec + time.tv_usec;
			} else
				sp->lcp.magic = rmagic;
		}
		if (sp->lcp.state != LCP_STATE_ACK_SENT) {
			/* Go to closed state. */
			sp->lcp.state = LCP_STATE_CLOSED;
			sp->ipcp.state = IPCP_STATE_CLOSED;
			sp->chap.state = CHAP_STATE_CLOSED;
		}
		/* The link will be renegotiated after timeout,
		 * to avoid endless req-nack loop. */
		UNTIMO (sp);
		TIMO (sp, 2);
		break;
	case LCP_CONF_REJ:
		if (h->ident != sp->lcp.confid)
			break;
		UNTIMO (sp);
		/* Check CHAP mode. */
		if (len > 4)
			sppp_lcp_rej_parse_options (sp, h, len);
		/* Initiate renegotiation. */
		sppp_lcp_open (sp);
		if (sp->lcp.state != LCP_STATE_ACK_SENT) {
			/* Go to closed state. */
			sp->lcp.state = LCP_STATE_CLOSED;
			sp->ipcp.state = IPCP_STATE_CLOSED;
			sp->chap.state = CHAP_STATE_CLOSED;
		}
		break;
	case LCP_TERM_REQ:
		UNTIMO (sp);
		/* Send Terminate-Ack packet. */
		sppp_cp_send (sp, PPP_LCP, LCP_TERM_ACK, h->ident, 0, 0);
		/* Go to closed state. */
		sp->lcp.state = LCP_STATE_CLOSED;
		sp->ipcp.state = IPCP_STATE_CLOSED;
		sp->chap.state = CHAP_STATE_CLOSED;
		sp->chap.mode = sp->chap.admin;
		/* Initiate renegotiation. */
		sppp_lcp_open (sp);
		break;
	case LCP_TERM_ACK:
	case LCP_CODE_REJ:
	case LCP_PROTO_REJ:
		/* Ignore for now. */
		break;
	case LCP_DISC_REQ:
		/* Discard the packet. */
		break;
	case LCP_ECHO_REQ:
		if (len < 8) {
			if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: invalid lcp echo request packet length: %d bytes\n",
					ifp->if_name, ifp->if_unit, len);
			break;
		}
		if (ntohl (*(long*)(h+1)) == sp->lcp.magic) {
			/* Line loopback mode detected. */
			printf ("%s%d: loopback\n", ifp->if_name, ifp->if_unit);
			if_down (ifp);
			qflush (&sp->pp_fastq);

			/* Shut down the PPP link. */
			sp->lcp.state = LCP_STATE_CLOSED;
			sp->ipcp.state = IPCP_STATE_CLOSED;
			sp->chap.state = CHAP_STATE_CLOSED;
			UNTIMO (sp);
			/* Initiate negotiation. */
			sppp_lcp_open (sp);
			break;
		}
		*(long*)(h+1) = htonl (sp->lcp.magic);
		sppp_cp_send (sp, PPP_LCP, LCP_ECHO_REPLY, h->ident, len-4, h+1);
		break;
	case LCP_ECHO_REPLY:
		if (h->ident != sp->lcp.echoid)
			break;
		if (len < 8) {
			if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: invalid lcp echo reply packet length: %d bytes\n",
					ifp->if_name, ifp->if_unit, len);
			break;
		}
		if (ntohl (*(long*)(h+1)) != sp->lcp.magic)
			sp->pp_alivecnt = 0;
		break;
	}
}

/*
 * Handle incoming Cisco keepalive protocol packets.
 */
void sppp_cisco_input (struct sppp *sp, struct mbuf *m)
{
	struct cisco_packet *h;
	struct ifaddr *ifa;
	struct ifnet *ifp = &sp->pp_if;

	if (m->m_pkthdr.len < CISCO_PACKET_LEN) {
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: invalid cisco packet length: %d bytes\n",
				ifp->if_name, ifp->if_unit, m->m_pkthdr.len);
		return;
	}
	h = mtod (m, struct cisco_packet*);
	if (ifp->if_flags & IFF_DEBUG)
		printf ("%s%d: cisco input: %d bytes <%lxh %lxh %lxh %xh %xh-%xh>\n",
			ifp->if_name, ifp->if_unit, m->m_pkthdr.len,
			ntohl (h->type), h->par1, h->par2, h->rel,
			h->time0, h->time1);
	switch (ntohl (h->type)) {
	default:
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: unknown cisco packet type: 0x%lx\n",
				ifp->if_name, ifp->if_unit, ntohl (h->type));
		break;
	case CISCO_ADDR_REPLY:
		/* Reply on address request, ignore */
		break;
	case CISCO_KEEPALIVE_REQ:
		sp->pp_alivecnt = 0;
		sp->pp_rseq = ntohl (h->par1);
		if (sp->pp_seq == sp->pp_rseq) {
			/* Local and remote sequence numbers are equal.
			 * Probably, the line is in loopback mode. */
			if (sp->pp_loopcnt >= MAXALIVECNT) {
				printf ("%s%d: loopback\n",
					ifp->if_name, ifp->if_unit);
				sp->pp_loopcnt = 0;
				if (ifp->if_flags & IFF_UP) {
					if_down (ifp);
					qflush (&sp->pp_fastq);
				}
			}
			++sp->pp_loopcnt;

			/* Generate new local sequence number */
			sp->pp_seq ^= time.tv_sec ^ time.tv_usec;
			break;
		}
		sp->pp_loopcnt = 0;
		if (! (ifp->if_flags & IFF_UP) &&
		    (ifp->if_flags & IFF_RUNNING)) {
			ifp->if_flags |= IFF_UP;
			printf ("%s%d: up\n", ifp->if_name, ifp->if_unit);
		}
		break;
	case CISCO_ADDR_REQ:
		ifa = myifaddr (ifp);
		if (! ifa) 
			return;
		sppp_cisco_send (sp, CISCO_ADDR_REPLY,
			ntohl (((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr),
			ntohl (((struct sockaddr_in*)ifa->ifa_netmask)->sin_addr.s_addr));
		break;
	}
}

/*
 * Send PPP LCP packet.
 */
void sppp_cp_send (struct sppp *sp, u_short proto, u_char type,
	u_char ident, u_short len, void *data)
{
	struct ppp_header *h;
	struct lcp_header *lh;
	struct mbuf *m;
	struct ifnet *ifp = &sp->pp_if;

	if (len > MHLEN - PPP_HEADER_LEN - LCP_HEADER_LEN)
		len = MHLEN - PPP_HEADER_LEN - LCP_HEADER_LEN;
	MGETHDR (m, M_DONTWAIT, MT_DATA);
	if (! m)
		return;
	m->m_pkthdr.len = m->m_len = PPP_HEADER_LEN + LCP_HEADER_LEN + len;
	m->m_pkthdr.rcvif = 0;

	h = mtod (m, struct ppp_header*);
	h->address = PPP_ALLSTATIONS;        /* broadcast address */
	h->control = PPP_UI;                 /* Unnumbered Info */
	h->protocol = htons (proto);         /* Link Control Protocol */

	lh = (struct lcp_header*) (h + 1);
	lh->type = type;
	lh->ident = ident;
	lh->len = htons (LCP_HEADER_LEN + len);
	if (len)
		bcopy (data, lh+1, len);

	if (ifp->if_flags & IFF_DEBUG) {
		printf ("%s%d: ", ifp->if_name, ifp->if_unit);
		if (proto == PPP_LCP)
			printf ("lcp output(%c) <%s",
				sppp_state_name (sp->lcp.state),
				sppp_lcp_type_name (lh->type));
		else
			printf ("ipcp output(%c) <%s",
				sppp_state_name (sp->ipcp.state),
				sppp_ipcp_type_name (lh->type));
		printf (" id=%xh len=%xh", lh->ident, ntohs (lh->len));
		if (len)
			sppp_print_bytes ((u_char*) (lh+1), len);
		printf (">\n");
	}
	if (IF_QFULL (&sp->pp_fastq)) {
		IF_DROP (&ifp->if_snd);
		m_freem (m);
	} else
		IF_ENQUEUE (&sp->pp_fastq, m);
	if (! (ifp->if_flags & IFF_OACTIVE))
		(*ifp->if_start) (ifp);
	ifp->if_obytes += m->m_pkthdr.len + 3;
}

/*
 * Send Cisco keepalive packet.
 */
void sppp_cisco_send (struct sppp *sp, int type, long par1, long par2)
{
	struct ppp_header *h;
	struct cisco_packet *ch;
	struct mbuf *m;
	struct ifnet *ifp = &sp->pp_if;
	u_long t = (time.tv_sec - boottime.tv_sec) * 1000;

	MGETHDR (m, M_DONTWAIT, MT_DATA);
	if (! m)
		return;
	m->m_pkthdr.len = m->m_len = PPP_HEADER_LEN + CISCO_PACKET_LEN;
	m->m_pkthdr.rcvif = 0;

	h = mtod (m, struct ppp_header*);
	h->address = CISCO_MULTICAST;
	h->control = 0;
	h->protocol = htons (CISCO_KEEPALIVE);

	ch = (struct cisco_packet*) (h + 1);
	ch->type = htonl (type);
	ch->par1 = htonl (par1);
	ch->par2 = htonl (par2);
	ch->rel = -1;
	ch->time0 = htons ((u_short) (t >> 16));
	ch->time1 = htons ((u_short) t);

	if (ifp->if_flags & IFF_DEBUG)
		printf ("%s%d: cisco output: <%lxh %lxh %lxh %xh %xh-%xh>\n",
			ifp->if_name, ifp->if_unit, ntohl (ch->type), ch->par1,
			ch->par2, ch->rel, ch->time0, ch->time1);

	if (IF_QFULL (&sp->pp_fastq)) {
		IF_DROP (&ifp->if_snd);
		m_freem (m);
	} else
		IF_ENQUEUE (&sp->pp_fastq, m);
	if (! (ifp->if_flags & IFF_OACTIVE))
		(*ifp->if_start) (ifp);
	ifp->if_obytes += m->m_pkthdr.len + 3;
}

/*
 * Process an ioctl request.  Called on low priority level.
 */
int sppp_ioctl (struct ifnet *ifp, int cmd, void *data)
{
	struct ifreq *ifr = (struct ifreq*) data;
	struct sppp *sp = (struct sppp*) ifp;
	int s, going_up, going_down;

	switch (cmd) {
	default:
		return (EINVAL);

	case SIOCAIFADDR:
	case SIOCSIFDSTADDR:
		break;

	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		/* fall through... */

	case SIOCSIFFLAGS:
		s = splimp ();
		going_up   = (ifp->if_flags & IFF_UP) &&
			     ! (ifp->if_flags & IFF_RUNNING);
		going_down = ! (ifp->if_flags & IFF_UP) &&
			      (ifp->if_flags & IFF_RUNNING);
		if (going_up || going_down) {
			/* Shut down the link. */
			ifp->if_flags &= ~IFF_RUNNING;
			if (! (sp->pp_flags & PP_CISCO) &&
			    ! (sp->pp_flags & PP_FR)) {
				sp->lcp.state = LCP_STATE_CLOSED;
				sp->ipcp.state = IPCP_STATE_CLOSED;
				sp->chap.state = CHAP_STATE_CLOSED;
				UNTIMO (sp);
			}
		}
		if (going_up) {
			/* Interface is starting -- initiate negotiation. */
			ifp->if_flags |= IFF_RUNNING;
			if (! (sp->pp_flags & PP_CISCO) &&
			    ! (sp->pp_flags & PP_FR))
				sppp_lcp_open (sp);
		}
		splx (s);
		break;

#ifdef SIOCSIFMTU
#ifndef ifr_mtu
#define ifr_mtu ifr_metric
#endif
	case SIOCSIFMTU:
		if (ifr->ifr_mtu < 128 || ifr->ifr_mtu > PP_MTU)
			return (EINVAL);
		ifp->if_mtu = ifr->ifr_mtu;
		break;
#endif
#ifdef SLIOCSETMTU
	case SLIOCSETMTU:
		if (*(short*)data < 128 || *(short*)data > PP_MTU)
			return (EINVAL);
		ifp->if_mtu = *(short*)data;
		break;
#endif
#ifdef SIOCGIFMTU
	case SIOCGIFMTU:
		ifr->ifr_mtu = ifp->if_mtu;
		break;
#endif
#ifdef SLIOCGETMTU
	case SLIOCGETMTU:
		*(short*)data = ifp->if_mtu;
		break;
#endif
#ifdef MULTICAST
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;
#endif
	}
	return (0);
}

/*
 * Analyze the IPCP Configure-Request options list
 * for the presence of unknown options.
 * If the request contains unknown options, build and
 * send Configure-reject packet, containing only unknown options.
 */
int sppp_ipcp_conf_parse_options (struct sppp *sp, struct lcp_header *h,
	int len)
{
	u_char *buf, *r, *p;
	int rlen;
	u_long addr, peeraddr;
	struct ifaddr *ifa = 0;

	len -= 4;
	buf = r = malloc (len, M_TEMP, M_NOWAIT);
	if (! buf)
		return 0;

	p = (void*) (h+1);
	for (rlen=0; len>1 && p[1]; len-=p[1], p+=p[1]) {
		if (*p == IPCP_OPT_ADDRESS && len >= 6 && p[1] == 6) {
			/* Get an IP address of the peer. */
			peeraddr = (u_long)p[2] << 24 | (u_long)p[3] << 16 | 
				p[4] << 8 | p[5];
			ifa = myifaddr (&sp->pp_if);
			if (ifa)
				addr = ntohl (((struct sockaddr_in*)
					ifa->ifa_dstaddr)->sin_addr.s_addr);
			else
				addr = 0;
			if (peeraddr == addr)
				continue;
			p[2] = addr >> 24;
			p[3] = addr >> 16;
			p[4] = addr >> 8;
			p[5] = addr;
		}
		/* Add the option to rejected list. */
		bcopy (p, r, p[1]);
		r += p[1];
		rlen += p[1];
	}
	if (rlen) {
		sppp_cp_send (sp, PPP_IPCP, IPCP_CONF_REJ, h->ident, rlen, buf);
		free (buf, M_TEMP);
		return 0;
	}
	return 1;
}

/*
 * Analyze the LCP Configure-Request options list
 * for the presence of unknown options.
 * If the request contains unknown options, build and
 * send Configure-reject packet, containing only unknown options.
 */
int sppp_lcp_conf_parse_options (struct sppp *sp, struct lcp_header *h,
	int len, u_long *magic)
{
	u_char *buf, *r, *p;
	int rlen;

	len -= 4;
	buf = r = malloc (len, M_TEMP, M_NOWAIT);
	if (! buf)
		return 0;

	p = (void*) (h+1);
	for (rlen=0; len>1 && p[1]; len-=p[1], p+=p[1]) {
		switch (*p) {
		case LCP_OPT_MAGIC:
			/* Magic number -- extract. */
			if (len >= 6 && p[1] == 6) {
				*magic = (u_long)p[2] << 24 |
					(u_long)p[3] << 16 | p[4] << 8 | p[5];
				continue;
			}
			break;

		case LCP_OPT_ASYNC_MAP:
			/* Async control character map -- check to be zero. */
			if (len >= 6 && p[1] == 6 && ! p[2] && ! p[3] &&
			    ! p[4] && ! p[5])
				continue;
			break;

		case LCP_OPT_AUTH_PROTO:
			/* Authentication protocol. */
			/* Reject, if administratively disabled. */
			if (sp->chap.admin == CHAP_MODE_OFF)
				break;

			/* If peer wants PAP - use PAP. */
			if (len >= 4 && p[1] == 4 &&
			    (p[2] << 8 | p[3]) == PPP_PAP) {
				sp->chap.mode = CHAP_MODE_PAP;
				continue;
			}

			/* Otherwise use CHAP. */
			if (len < 5 || p[1] != 5)
				break;
			if ((p[2] << 8 | p[3]) != PPP_CHAP) {
				/* Unknown protocol, we need CHAP. */
				p[2] = PPP_CHAP >> 8;
				p[3] = (u_char) PPP_CHAP;
				p[4] = CHAP_MD5;
				break;
			}
			if (p[4] == CHAP_MD5) {
				sp->chap.mode = CHAP_MODE_MD5;
				continue;
			}

			/* Unknown hash algorithm, we need MD5. */
			p[4] = CHAP_MD5;
			break;

		case LCP_OPT_MRU:
			/* Maximum receive unit -- always OK. */
			continue;

		default:
			/* Others not supported. */
			break;
		}
		/* Add the option to rejected list. */
		bcopy (p, r, p[1]);
		r += p[1];
		rlen += p[1];
	}
	if (rlen) {
		sppp_cp_send (sp, PPP_LCP, LCP_CONF_REJ, h->ident, rlen, buf);
		free (buf, M_TEMP);
		return 0;
	}
	return 1;
}

/*
 * Analyze the LCP Configure-Reject options list
 * for the presence of CHAP option.
 */
void sppp_lcp_rej_parse_options (struct sppp *sp, struct lcp_header *h, int len)
{
	u_char *p = (void*) (h+1);

	len -= 4;
	for (; len>1 && p[1]; len-=p[1], p+=p[1])
		if (*p == LCP_OPT_AUTH_PROTO) {
			/* Ignore, if authentication disabled. */
			if (sp->chap.admin == CHAP_MODE_OFF)
				continue;

			/* If peer rejects PAP - disable authentication. */
			if (len >= 4 && p[1] == 4 &&
			    (p[2] << 8 | p[3]) == PPP_PAP) {
				sp->chap.mode = CHAP_MODE_OFF;
				continue;
			}

			/* Expecting CHAP. */
			if (len < 5 || p[1] != 5 ||
			    (p[2] << 8 | p[3]) != PPP_CHAP)
				continue;

			/* If peer rejects CHAP - use PAP. */
			if (p[4] == CHAP_MD5)
				sp->chap.mode = CHAP_MODE_PAP;
		}
}

void sppp_ipcp_input (struct sppp *sp, struct mbuf *m)
{
	struct lcp_header *h;
	struct ifnet *ifp = &sp->pp_if;
	int len = m->m_pkthdr.len;

	if (len < 4) {
		/* if (ifp->if_flags & IFF_DEBUG) */
			printf ("%s%d: invalid ipcp packet length: %d bytes\n",
				ifp->if_name, ifp->if_unit, len);
		return;
	}
	h = mtod (m, struct lcp_header*);
	if (ifp->if_flags & IFF_DEBUG) {
		printf ("%s%d: ipcp input: %d bytes <%s id=%xh len=%xh",
			ifp->if_name, ifp->if_unit, len,
			sppp_ipcp_type_name (h->type), h->ident, ntohs (h->len));
		if (len > 4)
			sppp_print_bytes ((u_char*) (h+1), len-4);
		printf (">\n");
	}
	if (len > ntohs (h->len))
		len = ntohs (h->len);
	switch (h->type) {
	default:
		/* Unknown packet type -- send Code-Reject packet. */
		sppp_cp_send (sp, PPP_IPCP, IPCP_CODE_REJ, ++sp->pp_seq, len, h);
		break;
	case IPCP_CONF_REQ:
		if (len < 4) {
			if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: invalid ipcp configure request packet length: %d bytes\n",
					ifp->if_name, ifp->if_unit, len);
			return;
		}
		if (len>4 && !sppp_ipcp_conf_parse_options (sp, h, len)) {
			switch (sp->ipcp.state) {
			case IPCP_STATE_OPENED:
				/* Initiate renegotiation. */
				sppp_ipcp_open (sp);
				/* fall through... */
			case IPCP_STATE_ACK_SENT:
				/* Go to closed state. */
				sp->ipcp.state = IPCP_STATE_CLOSED;
			}
			break;
		}
		/* Send Configure-Ack packet. */
		sppp_cp_send (sp, PPP_IPCP, IPCP_CONF_ACK, h->ident, len-4, h+1);
		/* Change the state. */
		switch (sp->ipcp.state) {
		case IPCP_STATE_ACK_RCVD:
			sp->ipcp.state = IPCP_STATE_OPENED;
			if (sp->chap.admin != CHAP_MODE_OFF)
				TIMO (sp, 2);
			break;
		case IPCP_STATE_OPENED:
			/* Initiate renegotiation. */
			sppp_ipcp_open (sp);
			/* fall through... */
		default:
			sp->ipcp.state = IPCP_STATE_ACK_SENT;
		}
		break;
	case IPCP_CONF_ACK:
		if (h->ident != sp->ipcp.confid)
			break;
		UNTIMO (sp);
		switch (sp->ipcp.state) {
		case IPCP_STATE_CLOSED:
			sp->ipcp.state = IPCP_STATE_ACK_RCVD;
			TIMO (sp, 5);
			break;
		case IPCP_STATE_ACK_SENT:
			sp->ipcp.state = IPCP_STATE_OPENED;
			if (sp->chap.admin != CHAP_MODE_OFF)
				TIMO (sp, 2);
			break;
		}
		break;
	case IPCP_CONF_NAK:
	case IPCP_CONF_REJ:
		if (h->ident != sp->ipcp.confid)
			break;
		UNTIMO (sp);
		/* Initiate renegotiation. */
		sppp_ipcp_open (sp);
		if (sp->ipcp.state != IPCP_STATE_ACK_SENT)
			/* Go to closed state. */
			sp->ipcp.state = IPCP_STATE_CLOSED;
		break;
	case IPCP_TERM_REQ:
		/* Send Terminate-Ack packet. */
		sppp_cp_send (sp, PPP_IPCP, IPCP_TERM_ACK, h->ident, 0, 0);
		/* Go to closed state. */
		sp->ipcp.state = IPCP_STATE_CLOSED;
		/* Initiate renegotiation. */
		sppp_ipcp_open (sp);
		break;
	case IPCP_TERM_ACK:
		/* Ignore for now. */
	case IPCP_CODE_REJ:
		/* Ignore for now. */
		break;
	}
}

void sppp_lcp_open (struct sppp *sp)
{
	char opt[11], *p = opt;

	if (! sp->lcp.magic)
		sp->lcp.magic = time.tv_sec + time.tv_usec;
	*p++ = LCP_OPT_MAGIC;
	*p++ = 6;
	*p++ = sp->lcp.magic >> 24;
	*p++ = sp->lcp.magic >> 16;
	*p++ = sp->lcp.magic >> 8;
	*p++ = sp->lcp.magic;
	switch (sp->chap.mode) {
	case CHAP_MODE_PAP:
		*p++ = LCP_OPT_AUTH_PROTO;
		*p++ = 4;
		*p++ = PPP_PAP >> 8;
		*p++ = (u_char) PPP_PAP;
		break;
	case CHAP_MODE_MD5:
		*p++ = LCP_OPT_AUTH_PROTO;
		*p++ = 5;
		*p++ = PPP_CHAP >> 8;
		*p++ = (u_char) PPP_CHAP;
		*p++ = CHAP_MD5;
		break;
	}
	sp->lcp.confid = ++sp->pp_seq;
	sppp_cp_send (sp, PPP_LCP, LCP_CONF_REQ, sp->lcp.confid,
		p - opt, &opt);
	TIMO (sp, 5);
}

void sppp_ipcp_open (struct sppp *sp)
{
	char opt[11], *p = opt;
	u_long addr;
	struct ifaddr *ifa;

	sp->ipcp.confid = ++sp->pp_seq;
	ifa = myifaddr (&sp->pp_if);
	if (ifa)
		addr = ntohl (((struct sockaddr_in*)
			ifa->ifa_addr)->sin_addr.s_addr);
	else
		addr = 0;
	*p++ = IPCP_OPT_ADDRESS;
	*p++ = 6;
	*p++ = addr >> 24;
	*p++ = addr >> 16;
	*p++ = addr >> 8;
	*p++ = addr;
	sppp_cp_send (sp, PPP_IPCP, IPCP_CONF_REQ, sp->ipcp.confid,
		p - opt, &opt);
	TIMO (sp, 5);
}

/*
 * Process PPP control protocol timeouts.
 */
void sppp_cp_timeout (void *arg)
{
	struct sppp *sp = (struct sppp*) arg;
	int s = splimp ();

	sp->pp_flags &= ~PP_TIMO;
	if (! (sp->pp_if.if_flags & IFF_RUNNING) ||
	    (sp->pp_flags & PP_CISCO) || (sp->pp_flags & PP_FR)) {
		splx (s);
		return;
	}
	switch (sp->lcp.state) {
	case LCP_STATE_CLOSED:
		/* No ACK for Configure-Request, retry. */
		sppp_lcp_open (sp);
		break;
	case LCP_STATE_ACK_RCVD:
		/* ACK got, but no Configure-Request for peer, retry. */
		sppp_lcp_open (sp);
		sp->lcp.state = LCP_STATE_CLOSED;
		break;
	case LCP_STATE_ACK_SENT:
		/* ACK sent but no ACK for Configure-Request, retry. */
		sppp_lcp_open (sp);
		break;
	case LCP_STATE_OPENED:
		/* LCP is already OK, try CHAP. */
		if (sp->chap.state != CHAP_STATE_OPENED) {
			sppp_chap_open (sp);
			break;
		}
		/* CHAP is OK, try IPCP. */
		switch (sp->ipcp.state) {
		case IPCP_STATE_CLOSED:
			/* No ACK for Configure-Request, retry. */
			sppp_ipcp_open (sp);
			break;
		case IPCP_STATE_ACK_RCVD:
			/* ACK got, but no Configure-Request for peer, retry. */
			sppp_ipcp_open (sp);
			sp->ipcp.state = IPCP_STATE_CLOSED;
			break;
		case IPCP_STATE_ACK_SENT:
			/* ACK sent but no ACK for Configure-Request, retry. */
			sppp_ipcp_open (sp);
			break;
		case IPCP_STATE_OPENED:
			/* IPCP is OK. */
			break;
		}
		break;
	}
	splx (s);
}

char *sppp_lcp_type_name (u_char type)
{
	static char buf [8];
	switch (type) {
	case LCP_CONF_REQ:   return ("conf-req");
	case LCP_CONF_ACK:   return ("conf-ack");
	case LCP_CONF_NAK:   return ("conf-nack");
	case LCP_CONF_REJ:   return ("conf-rej");
	case LCP_TERM_REQ:   return ("term-req");
	case LCP_TERM_ACK:   return ("term-ack");
	case LCP_CODE_REJ:   return ("code-rej");
	case LCP_PROTO_REJ:  return ("proto-rej");
	case LCP_ECHO_REQ:   return ("echo-req");
	case LCP_ECHO_REPLY: return ("echo-reply");
	case LCP_DISC_REQ:   return ("discard-req");
	}
	sprintf (buf, "%xh", type);
	return (buf);
}

char *sppp_ipcp_type_name (u_char type)
{
	static char buf [8];
	switch (type) {
	case IPCP_CONF_REQ: return ("conf-req");
	case IPCP_CONF_ACK: return ("conf-ack");
	case IPCP_CONF_NAK: return ("conf-nack");
	case IPCP_CONF_REJ: return ("conf-rej");
	case IPCP_TERM_REQ: return ("term-req");
	case IPCP_TERM_ACK: return ("term-ack");
	case IPCP_CODE_REJ: return ("code-rej");
	}
	sprintf (buf, "%xh", type);
	return (buf);
}

static char *sppp_chap_type_name (u_char type)
{
	static char buf [8];
	switch (type) {
	case CHAP_CHALLENGE: return ("challenge");
	case CHAP_RESPONSE:  return ("response");
	case CHAP_SUCCESS:   return ("success");
	case CHAP_FAILURE:   return ("failure");
	}
	sprintf (buf, "%xh", type);
	return (buf);
}

static char *sppp_pap_type_name (u_char type)
{
	static char buf [8];
	switch (type) {
	case PAP_REQUEST: return ("request");
	case PAP_ACK:     return ("ack");
	case PAP_NACK:    return ("nack");
	}
	sprintf (buf, "%xh", type);
	return (buf);
}

void sppp_print_bytes (u_char *p, u_short len)
{
	printf (" %x", *p++);
	while (--len > 0)
		printf ("-%x", *p++);
}

static void sppp_print_string (char *p, u_short len)
{
	while (len-- > 0)
		printf ("%c", *p++);
}

static void sppp_chap_send (struct sppp *sp, u_char type, u_char id,
	u_char mlen, u_char *msg, u_char vlen, u_char *val)
{
	struct ppp_header *h;
	struct lcp_header *lh;
	struct mbuf *m;
	struct ifnet *ifp = &sp->pp_if;
	u_char *p;
	int len;

	len = mlen;
	if (vlen)
		len += 1 + vlen;
	if (len > MHLEN - PPP_HEADER_LEN - LCP_HEADER_LEN)
		return;
	MGETHDR (m, M_DONTWAIT, MT_DATA);
	if (! m)
		return;
	m->m_pkthdr.len = m->m_len = PPP_HEADER_LEN + LCP_HEADER_LEN + len;
	m->m_pkthdr.rcvif = 0;

	h = mtod (m, struct ppp_header*);
	h->address = PPP_ALLSTATIONS;           /* broadcast address */
	h->control = PPP_UI;                    /* Unnumbered Info */
	h->protocol = htons (PPP_CHAP);         /* Link Control Protocol */

	lh = (struct lcp_header*) (h + 1);
	lh->type = type;
	lh->ident = id;
	lh->len = htons (LCP_HEADER_LEN + len);
	p = (u_char*) (lh+1);
	if (vlen) {
		*p++ = vlen;
		bcopy (val, p, vlen);
		p += vlen;
	}
	bcopy (msg, p, mlen);
	if (ifp->if_flags & IFF_DEBUG) {
		printf ("%s%d: ", ifp->if_name, ifp->if_unit);
		printf ("chap output(%c) <%s",
			sp->chap.state == CHAP_STATE_OPENED ? 'O' : 'C',
			sppp_chap_type_name (lh->type));
		printf (" id=%xh len=%xh", lh->ident, ntohs (lh->len));
		if (len)
			sppp_print_bytes ((u_char*) (lh+1), len);
		printf (">\n");
	}
	if (IF_QFULL (&sp->pp_fastq)) {
		IF_DROP (&ifp->if_snd);
		m_freem (m);
	} else
		IF_ENQUEUE (&sp->pp_fastq, m);
	if (! (ifp->if_flags & IFF_OACTIVE))
		(*ifp->if_start) (ifp);
	ifp->if_obytes += m->m_pkthdr.len + 3;
}

static void sppp_pap_send (struct sppp *sp, u_char type, u_char id, u_char mlen,
	u_char *msg, u_char vlen, u_char *val)
{
	struct ppp_header *h;
	struct lcp_header *lh;
	struct mbuf *m;
	struct ifnet *ifp = &sp->pp_if;
	u_char *p;
	int len;

	len = 1 + mlen;
	if (vlen)
		len += 1 + vlen;
	if (len > MHLEN - PPP_HEADER_LEN - LCP_HEADER_LEN)
		return;
	MGETHDR (m, M_DONTWAIT, MT_DATA);
	if (! m)
		return;
	m->m_pkthdr.len = m->m_len = PPP_HEADER_LEN + LCP_HEADER_LEN + len;
	m->m_pkthdr.rcvif = 0;

	h = mtod (m, struct ppp_header*);
	h->address = PPP_ALLSTATIONS;           /* broadcast address */
	h->control = PPP_UI;                    /* Unnumbered Info */
	h->protocol = htons (PPP_PAP);          /* Link Control Protocol */

	lh = (struct lcp_header*) (h + 1);
	lh->type = type;
	lh->ident = id;
	lh->len = htons (LCP_HEADER_LEN + len);
	p = (u_char*) (lh+1);
	bcopy (msg, p, mlen);
	p += mlen;
	if (vlen) {
		*p++ = vlen;
		bcopy (val, p, vlen);
	}
	if (ifp->if_flags & IFF_DEBUG) {
		printf ("%s%d: ", ifp->if_name, ifp->if_unit);
		printf ("pap output(%c) <%s",
			sp->chap.state == CHAP_STATE_OPENED ? 'O' : 'C',
			sppp_pap_type_name (lh->type));
		printf (" id=%xh len=%xh", lh->ident, ntohs (lh->len));
		if (len)
			sppp_print_bytes ((u_char*) (lh+1), len);
		printf (">\n");
	}
	if (IF_QFULL (&sp->pp_fastq)) {
		IF_DROP (&ifp->if_snd);
		m_freem (m);
	} else
		IF_ENQUEUE (&sp->pp_fastq, m);
	if (! (ifp->if_flags & IFF_OACTIVE))
		(*ifp->if_start) (ifp);
	ifp->if_obytes += m->m_pkthdr.len + 3;
}

void sppp_chap_open (struct sppp *sp)
{
	if (sp->chap.state == CHAP_STATE_OPENED) {
done:		if (sp->ipcp.state != IPCP_STATE_OPENED)
			sppp_ipcp_open (sp);
		return;
	}
	if (sp->chap.mode == CHAP_MODE_OFF) {
		sp->chap.state = CHAP_STATE_OPENED;
		goto done;
	}
	sp->chap.state = CHAP_STATE_CLOSED;
	sp->chap.lastid = ++sp->pp_seq;
	if (sp->chap.mode == CHAP_MODE_PAP)
		sppp_pap_send (sp, PAP_REQUEST, sp->chap.lastid,
			strnlen (sp->chap.name, sizeof (sp->chap.name)),
			sp->chap.name,
			strnlen (sp->chap.passwd, sizeof (sp->chap.passwd)),
			sp->chap.passwd);
	else {
		/* Compute random challenge. */
		struct timeval tv;
		u_long *ch, seed;

		ch = (u_long*) sp->chap.challenge;
		microtime (&tv);
		seed = tv.tv_sec ^ tv.tv_usec;
		ch [0] = seed ^ random ();
		ch [1] = seed ^ random ();
		ch [2] = seed ^ random ();
		ch [3] = seed ^ random ();
		sppp_chap_send (sp, CHAP_CHALLENGE, sp->chap.lastid,
			strnlen (sp->chap.name, sizeof (sp->chap.name)),
			sp->chap.name, sizeof (sp->chap.challenge),
			sp->chap.challenge);
	}
	TIMO (sp, 5);
}

/*
 * Handle incoming CHAP packets.
 */
void sppp_chap_input (struct sppp *sp, struct mbuf *m)
{
	struct lcp_header *h;
	struct ifnet *ifp = &sp->pp_if;
	int len = m->m_pkthdr.len;
	u_char *value, *name, digest [16];
	int value_len, name_len;
	MD5_CTX ctx;

	if (len < 4) {
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: invalid chap packet length: %d bytes\n",
				ifp->if_name, ifp->if_unit, len);
		return;
	}
	h = mtod (m, struct lcp_header*);
	if (len > ntohs (h->len))
		len = ntohs (h->len);

	switch (h->type) {
	default:
		/* Unknown CHAP packet type -- ignore. */
		if (ifp->if_flags & IFF_DEBUG) {
			printf ("%s%d: unknown chap input: %d bytes <%s id=%xh len=%xh",
				ifp->if_name, ifp->if_unit, len,
				sppp_chap_type_name (h->type), h->ident, ntohs (h->len));
			if (len > 4)
				sppp_print_bytes ((u_char*) (h+1), len-4);
			printf (">\n");
		}
		break;

	case CHAP_CHALLENGE:
		value = 1 + (u_char*) (h+1);
		value_len = value [-1];
		name = value + value_len;
		name_len = len - value_len - 5;
		if (name_len < 0) {
			if (ifp->if_flags & IFF_DEBUG) {
				printf ("%s%d: corrupted chap input: %d bytes <%s id=%xh len=%xh",
					ifp->if_name, ifp->if_unit, len,
					sppp_chap_type_name (h->type), h->ident, ntohs (h->len));
				if (len > 4)
					sppp_print_bytes ((u_char*) (h+1), len-4);
				printf (">\n");
			}
			break;
		}
		if (ifp->if_flags & IFF_DEBUG) {
			printf ("%s%d: chap input: %d bytes <%s id=%xh len=%xh name=",
				ifp->if_name, ifp->if_unit, len,
				sppp_chap_type_name (h->type), h->ident, ntohs (h->len));
			sppp_print_string ((char*) name, name_len);
			printf (" value=");
			sppp_print_bytes (value, value_len);
			printf (">\n");
		}

		/* Compute reply value. */
		MD5Init (&ctx);
		MD5Update (&ctx, &h->ident, 1);
		MD5Update (&ctx, sp->chap.passwd,
			strnlen (sp->chap.passwd,
				sizeof (sp->chap.passwd)));
		MD5Update (&ctx, value, value_len);
		MD5Final (digest, &ctx);

		sppp_chap_send (sp, CHAP_RESPONSE, h->ident, name_len,
			name, sizeof (digest), digest);
		break;

	case CHAP_RESPONSE:
		value = 1 + (u_char*) (h+1);
		value_len = value [-1];
		name = value + value_len;
		name_len = len - value_len - 5;
		if (name_len < 0) {
			if (ifp->if_flags & IFF_DEBUG) {
				printf ("%s%d: corrupted chap input: %d bytes <%s id=%xh len=%xh",
					ifp->if_name, ifp->if_unit, len,
					sppp_chap_type_name (h->type), h->ident, ntohs (h->len));
				if (len > 4)
					sppp_print_bytes ((u_char*) (h+1), len-4);
				printf (">\n");
			}
			break;
		}
		if (ifp->if_flags & IFF_DEBUG) {
			printf ("%s%d: chap input: %d bytes <%s id=%xh len=%xh name=",
				ifp->if_name, ifp->if_unit, len,
				sppp_chap_type_name (h->type), h->ident, ntohs (h->len));
			sppp_print_string ((char*) name, name_len);
			printf (" value=");
			sppp_print_bytes (value, value_len);
			printf (">\n");
		}
		if (value_len != sizeof (sp->chap.challenge)) {
			if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: bad hash value length: %d bytes, should be %d\n",
					ifp->if_name, ifp->if_unit, value_len,
					sizeof (sp->chap.challenge));
			break;
		}

		MD5Init (&ctx);
		MD5Update (&ctx, &h->ident, 1);
		MD5Update (&ctx, sp->chap.passwd,
			strnlen (sp->chap.passwd,
				sizeof (sp->chap.passwd)));
		MD5Update (&ctx, sp->chap.challenge,
			sizeof (sp->chap.challenge));
		MD5Final (digest, &ctx);

		if (bcmp (digest, value, value_len) != 0) {
			sppp_chap_send (sp, CHAP_FAILURE, h->ident, 9,
				(u_char*) "Failed...", 0, 0);
			break;
		}
		sppp_chap_send (sp, CHAP_SUCCESS, h->ident, 8,
			(u_char*) "Welcome!", 0, 0);
		sp->chap.state = CHAP_STATE_OPENED;
		if (sp->ipcp.state != IPCP_STATE_OPENED)
			sppp_ipcp_open (sp);
		break;

	case CHAP_SUCCESS:
		if (ifp->if_flags & IFF_DEBUG) {
			printf ("%s%d: chap success: ", ifp->if_name, ifp->if_unit);
			sppp_print_string ((char*) (h+1), len-4);
			printf ("\n");
		}
		break;

	case CHAP_FAILURE:
		if (ifp->if_flags & IFF_DEBUG) {
			printf ("%s%d: chap failure: ", ifp->if_name, ifp->if_unit);
			sppp_print_string ((char*) (h+1), len-4);
			printf ("\n");
		}
		break;
	}
}

/*
 * Handle incoming PAP packets.
 */
void sppp_pap_input (struct sppp *sp, struct mbuf *m)
{
	struct lcp_header *h;
	struct ifnet *ifp = &sp->pp_if;
	int len = m->m_pkthdr.len;
	u_char *name, *passwd;
	int name_len, passwd_len;

	if (len < 6) {
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: invalid pap packet length: %d bytes\n",
				ifp->if_name, ifp->if_unit, len);
		return;
	}
	h = mtod (m, struct lcp_header*);
	if (len > ntohs (h->len))
		len = ntohs (h->len);
	switch (h->type) {
	default:
		/* Unknown PAP packet type -- ignore. */
		if (ifp->if_flags & IFF_DEBUG) {
			printf ("%s%d: corrupted pap input: %d bytes <%s id=%xh len=%xh",
				ifp->if_name, ifp->if_unit, len,
				sppp_pap_type_name (h->type), h->ident, ntohs (h->len));
			if (len > 4)
				sppp_print_bytes ((u_char*) (h+1), len-4);
			printf (">\n");
		}
		break;

	case PAP_REQUEST:
		name = 1 + (u_char*) (h+1);
		name_len = name [-1];
		passwd = name + name_len + 1;
		if (name_len > len-6 ||
		    (passwd_len = passwd [-1]) > len - 6 - name_len) {
			if (ifp->if_flags & IFF_DEBUG) {
				printf ("%s%d: corrupted pap input: %d bytes <%s id=%xh len=%xh",
					ifp->if_name, ifp->if_unit, len,
					sppp_pap_type_name (h->type), h->ident, ntohs (h->len));
				if (len > 4)
					sppp_print_bytes ((u_char*) (h+1), len-4);
				printf (">\n");
			}
			break;
		}
		if (ifp->if_flags & IFF_DEBUG) {
			printf ("%s%d: pap input: %d bytes <%s id=%xh len=%xh name=",
				ifp->if_name, ifp->if_unit, len,
				sppp_pap_type_name (h->type), h->ident,
				ntohs (h->len));
			sppp_print_string ((char*) name, name_len);
			printf (" passwd=");
			sppp_print_string ((char*) passwd, passwd_len);
			printf ("\n");
		}
		if (name_len > sizeof (sp->chap.name) ||
		    passwd_len > sizeof (sp->chap.passwd) ||
		    ! equal (name, sp->chap.name, name_len) ||
		    ! equal (passwd, sp->chap.passwd, passwd_len)) {
			sppp_pap_send (sp, PAP_NACK, h->ident, 9,
				(u_char*) "Failed...", 0, 0);
			break;
		}
		sppp_pap_send (sp, PAP_ACK, h->ident, 8,
			(u_char*) "Welcome!", 0, 0);
		sp->chap.state = CHAP_STATE_OPENED;
		if (sp->ipcp.state != IPCP_STATE_OPENED)
			sppp_ipcp_open (sp);
		break;

	case PAP_ACK:
		if (ifp->if_flags & IFF_DEBUG) {
			printf ("%s%d: pap success: ", ifp->if_name, ifp->if_unit);
			sppp_print_string ((char*) (h+1), len-4);
			printf ("\n");
		}
		break;

	case PAP_NACK:
		if (ifp->if_flags & IFF_DEBUG) {
			printf ("%s%d: pap failure: ", ifp->if_name, ifp->if_unit);
			sppp_print_string ((char*) (h+1), len-4);
			printf ("\n");
		}
		break;
	}
}

/*
 * Process the frame relay Inverse ARP request.
 */
static void sppp_fr_arp (struct sppp *sp, struct arp_req *req,
	u_short his_hardware_address)
{
	struct ifnet *ifp = &sp->pp_if;
	struct mbuf *m;
	struct arp_req *reply;
	u_char *h;
	u_short my_hardware_address;
	u_long his_ip_address, my_ip_address;
	struct ifaddr *ifa;

	if (ntohs (req->htype) != ARPHRD_FRELAY ||
	    ntohs (req->ptype) != ETHERTYPE_IP) {
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: Invalid ARP hardware/protocol type = 0x%x/0x%x\n",
				ifp->if_name, ifp->if_unit,
				ntohs (req->htype), ntohs (req->ptype));
		return;
	}
	if (req->halen != 2 || req->palen != 4) {
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: Invalid ARP hardware/protocol address length = %d/%d\n",
				ifp->if_name, ifp->if_unit,
				req->halen, req->palen);
		return;
	}
	switch (ntohs (req->op)) {
	default:
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: Invalid ARP op = 0x%x\n",
				ifp->if_name, ifp->if_unit, ntohs (req->op));
		return;

	case ARPOP_INVREPLY:
		/* Ignore. */
		return;

	case ARPOP_INVREQUEST:
		my_hardware_address = ntohs (req->htarget);
		his_ip_address = ntohs (req->psource1) << 16 | 
			ntohs (req->psource2);
		my_ip_address = ntohs (req->ptarget1) << 16 | 
			ntohs (req->ptarget2);
		break;
	}
	if (ifp->if_flags & IFF_DEBUG)
		printf ("%s%d: got ARP request, source=0x%04x/%d.%d.%d.%d, target=0x%04x/%d.%d.%d.%d\n",
			ifp->if_name, ifp->if_unit, ntohs (req->hsource),
			(unsigned char) (his_ip_address >> 24),
			(unsigned char) (his_ip_address >> 16),
			(unsigned char) (his_ip_address >> 8),
			(unsigned char) his_ip_address,
			my_hardware_address,
			(unsigned char) (my_ip_address >> 24),
			(unsigned char) (my_ip_address >> 16),
			(unsigned char) (my_ip_address >> 8),
			(unsigned char) my_ip_address);

	ifa = myifaddr (ifp);
	if (! ifa)
		return;
	my_ip_address = ntohl (((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr);
	if (! my_ip_address)
		return;         /* nothing to reply */

	/* Send the Inverse ARP reply. */
	MGETHDR (m, M_DONTWAIT, MT_DATA);
	if (! m)
		return;
	m->m_pkthdr.len = m->m_len = 10 + sizeof (*reply);
	m->m_pkthdr.rcvif = 0;

	h = mtod (m, u_char*);
	reply = (struct arp_req*) (h + 10);

	h[0] = his_hardware_address >> 8;
	h[1] = his_hardware_address;
	h[2] = PPP_UI;
	h[3] = FR_PADDING;
	h[4] = FR_SNAP;
	h[5] = 0;
	h[6] = 0;
	h[7] = 0;
	*(short*) (h+8) = htons (ETHERTYPE_ARP);

	reply->htype    = htons (ARPHRD_FRELAY);
	reply->ptype    = htons (ETHERTYPE_IP);
	reply->halen    = 2;
	reply->palen    = 4;
	reply->op       = htons (ARPOP_INVREPLY);
	reply->hsource  = htons (my_hardware_address);
	reply->psource1 = htonl (my_ip_address);
	reply->psource2 = htonl (my_ip_address) >> 16;
	reply->htarget  = htons (his_hardware_address);
	reply->ptarget1 = htonl (his_ip_address);
	reply->ptarget2 = htonl (his_ip_address) >> 16;

	if (ifp->if_flags & IFF_DEBUG)
		printf ("%s%d: send ARP reply, source=0x%04x/%d.%d.%d.%d, target=0x%04x/%d.%d.%d.%d\n",
			ifp->if_name, ifp->if_unit, my_hardware_address,
			(unsigned char) (my_ip_address >> 24),
			(unsigned char) (my_ip_address >> 16),
			(unsigned char) (my_ip_address >> 8),
			(unsigned char) my_ip_address,
			his_hardware_address,
			(unsigned char) (his_ip_address >> 24),
			(unsigned char) (his_ip_address >> 16),
			(unsigned char) (his_ip_address >> 8),
			(unsigned char) his_ip_address);

	if (IF_QFULL (&sp->pp_fastq)) {
		IF_DROP (&ifp->if_snd);
		m_freem (m);
	} else
		IF_ENQUEUE (&sp->pp_fastq, m);
	if (! (ifp->if_flags & IFF_OACTIVE))
		(*ifp->if_start) (ifp);
	ifp->if_obytes += m->m_pkthdr.len + 3;
}

/*
 * Process the input signaling packet (DLCI 0).
 * The implemented protocol is ANSI T1.617 Annex D.
 */
static void sppp_fr_signal (struct sppp *sp, unsigned char *h, int len)
{
	struct ifnet *ifp = &sp->pp_if;
	u_char *p;
	int dlci;

	if (h[2] != PPP_UI || h[3] != FR_SIGNALING || h[4] != 0) {
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: Invalid signaling header\n",
				ifp->if_name, ifp->if_unit);
bad:            if (ifp->if_flags & IFF_DEBUG)
			prbytes (h, len);
		return;
	}
	if (h[5] == FR_MSG_ENQUIRY) {
		if (len == STATUS_ENQUIRY_SIZE &&
		    h[12] == (u_char) sp->pp_seq) {
			sp->pp_seq += time.tv_sec + time.tv_usec;
			printf ("%s%d: loopback detected\n",
				ifp->if_name, ifp->if_unit);
		}
		return;
	}
	if (h[5] != FR_MSG_STATUS) {
		if (ifp->if_flags & IFF_DEBUG)
			printf ("%s%d: Unknown signaling message: 0x%02x\n",
				ifp->if_name, ifp->if_unit, h[5]);
		goto bad;
	}

	/* Parse message fields. */
	for (p=h+6; p<h+len; ) {
		switch (*p) {
		default:
			if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: Unknown signaling field 0x%x\n",
					ifp->if_name, ifp->if_unit, *p);
			break;
		case FR_FLD_LSHIFT5:
		case FR_FLD_RTYPE:
			/* Ignore. */
			break;
		case FR_FLD_VERIFY:
			if (p[1] != 2) {
				if (ifp->if_flags & IFF_DEBUG)
					printf ("%s%d: Invalid signaling verify field length %d\n",
						ifp->if_name, ifp->if_unit, p[1]);
				break;
			}
			sp->pp_rseq = p[2];
			if (ifp->if_flags & IFF_DEBUG) {
				printf ("%s%d: got lmi reply rseq=%d, seq=%d",
					ifp->if_name, ifp->if_unit, p[2], p[3]);
				if (p[3] != (u_char) sp->pp_seq)
					printf (" (really %d)",
						(u_char) sp->pp_seq);
				printf ("\n");
			}
			break;
		case FR_FLD_PVC:
			if (p[1] < 3) {
				if (ifp->if_flags & IFF_DEBUG)
					printf ("%s%d: Invalid PVC status length %d\n",
						ifp->if_name, ifp->if_unit, p[1]);
				break;
			}
			dlci = (p[2] << 4 & 0x3f0) | (p[3] >> 3 & 0x0f);
			if (! sp->fr[0].dlci)
				sp->fr[0].dlci = dlci;
			if (sp->fr[0].status != p[4])
				printf ("%s%d: DLCI %d %s%s\n",
					ifp->if_name, ifp->if_unit, dlci,
					p[4] & FR_DLCI_DELETE ? "deleted" :
					p[4] & FR_DLCI_ACTIVE ? "active" : "passive",
					p[4] & FR_DLCI_NEW ? ", new" : "");
			sp->fr[0].status = p[4];
			break;
		}
		if (*p & 0x80)
			++p;
		else if (p < h+len+1 && p[1])
			p += 2 + p[1];
		else {
			if (ifp->if_flags & IFF_DEBUG)
				printf ("%s%d: Invalid signaling field 0x%x\n",
					ifp->if_name, ifp->if_unit, *p);
			goto bad;
		}
	}
}

/*
 * MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
 *
 * Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 * rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */
typedef unsigned char *POINTER;
typedef unsigned short int UINT2;
typedef unsigned long int UINT4;

#define PROTO_LIST(list) list

#define S11 7                   /* Constants for MD5Transform routine. */
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5Transform PROTO_LIST ((UINT4 [4], const unsigned char [64]));

#ifdef i386
#   define Encode bcopy
#   define Decode bcopy
#else /* i386 */
/*
 * Encodes input (UINT4) into output (unsigned char).
 * Assumes len is a multiple of 4.
 */
static void Encode (UINT4 *input, unsigned char *output, unsigned int len)
{
	unsigned int i, j;

	for (i=0, j=0; j<len; i++, j+=4) {
		output[j]   = (unsigned char) input[i];
		output[j+1] = (unsigned char) (input[i] >> 8);
		output[j+2] = (unsigned char) (input[i] >> 16);
		output[j+3] = (unsigned char) (input[i] >> 24);
	}
}

/*
 * Decodes input (unsigned char) into output (UINT4).
 * Assumes len is a multiple of 4.
 */
static void Decode (const unsigned char *input, UINT4 *output, unsigned int len)
{
	unsigned int i, j;

	for (i=0, j=0; j<len; i++, j+=4)
		output[i] = (UINT4) input[j]          |
			   ((UINT4) input[j+1] << 8)  |
			   ((UINT4) input[j+2] << 16) |
			   ((UINT4) input[j+3]) << 24);
}
#endif /* i386 */

static unsigned char PADDING[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions. */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits. */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/*
 * FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
	(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); }
#define GG(a, b, c, d, x, s, ac) { \
	(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); }
#define HH(a, b, c, d, x, s, ac) { \
	(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); }
#define II(a, b, c, d, x, s, ac) { \
	(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); }

/*
 * MD5 initialization. Begins an MD5 operation, writing a new context.
 */
static void MD5Init (MD5_CTX *context)
{
	context->count[0] = context->count[1] = 0;
	/* Load magic initialization constants. */
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

/*
 * MD5 block update operation. Continues an MD5 message-digest
 * operation, processing another message block, and updating the
 * context.
 */
static void MD5Update (MD5_CTX *context, const unsigned char *input,
	unsigned int inputLen)
{
	unsigned int i, index, partLen;

	/* Compute number of bytes mod 64 */
	index = (unsigned int)((context->count[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((context->count[0] += ((UINT4)inputLen << 3)) <
	    ((UINT4)inputLen << 3))
		context->count[1]++;
	context->count[1] += ((UINT4)inputLen >> 29);

	partLen = 64 - index;

	/* Transform as many times as possible. */
	if (inputLen >= partLen) {
		bcopy ((POINTER) input,
			(POINTER) &context->buffer[index], partLen);
		MD5Transform (context->state, context->buffer);

		for (i=partLen; i+63<inputLen; i+=64)
			MD5Transform (context->state, &input[i]);

		index = 0;
	} else
		i = 0;

	/* Buffer remaining input */
	bcopy ((POINTER) &input[i], (POINTER) &context->buffer[index],
		inputLen-i);
}

/*
 * MD5 finalization. Ends an MD5 message-digest operation, writing the
 * the message digest and zeroizing the context.
 */
static void MD5Final (unsigned char digest[16], MD5_CTX *context)
{
	unsigned char bits[8];
	unsigned int index, padLen;

	/* Save number of bits */
	Encode (context->count, bits, 8);

	/* Pad out to 56 mod 64. */
	index = (unsigned int)((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MD5Update (context, PADDING, padLen);

	/* Append length (before padding) */
	MD5Update (context, bits, 8);
	/* Store state in digest */
	Encode (context->state, digest, 16);

	/* Zeroize sensitive information. */
	bzero ((POINTER)context, sizeof (*context));
}

/*
 * MD5 basic transformation. Transforms state based on block.
 */
static void MD5Transform (UINT4 state[4], const unsigned char block[64])
{
	UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	Decode (block, x, 64);

	/* Round 1 */
	FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
	FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
	FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
	FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
	FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
	FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
	FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
	FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
	FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
	FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
	FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	/* Round 2 */
	GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
	GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
	GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
	GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
	GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
	GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
	GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
	GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
	GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
	GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
	GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
	GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
	HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
	HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
	HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
	HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
	HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
	HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
	HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
	HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
	HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
	II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
	II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
	II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
	II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
	II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
	II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
	II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
	II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
	II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	/* Zeroize sensitive information. */
	bzero ((POINTER)x, sizeof (x));
}

#ifdef SPPP_MODULE
/*
 * Loadable synchronous PPP driver stubs.
 */
#include <sys/conf.h>
#include <sys/exec.h>
#include <sys/sysent.h>
#include <sys/lkm.h>

extern void (*sppp_attach_ptr) (struct ifnet *ifp);
extern void (*sppp_detach_ptr) (struct ifnet *ifp);
extern void (*sppp_input_ptr) (struct ifnet *ifp, struct mbuf *m);
extern int (*sppp_ioctl_ptr) (struct ifnet *ifp, int cmd, void *data);
extern struct mbuf *(*sppp_dequeue_ptr) (struct ifnet *ifp);
extern int (*sppp_isempty_ptr) (struct ifnet *ifp);
extern void (*sppp_flush_ptr) (struct ifnet *ifp);

/*
 * Construct lkm_misc structure (see lkm.h).
 */
MOD_MISC("sppp")

/*
 * Function called when loading the driver.
 */
int sppp_load (struct lkm_table *lkmtp, int cmd)
{
	sppp_attach_ptr  = sppp_attach;
	sppp_detach_ptr  = sppp_detach;
	sppp_input_ptr   = sppp_input;
	sppp_ioctl_ptr   = sppp_ioctl;
	sppp_dequeue_ptr = sppp_dequeue;
	sppp_isempty_ptr = sppp_isempty;
	sppp_flush_ptr   = sppp_flush;
	return 0;
}

/*
 * Function called when unloading the driver.
 */
int sppp_unload (struct lkm_table *lkmtp, int cmd)
{
	if (spppq)
		return EBUSY;
	sppp_attach_ptr  = 0;
	sppp_detach_ptr  = 0;
	sppp_input_ptr   = 0;
	sppp_ioctl_ptr   = 0;
	sppp_dequeue_ptr = 0;
	sppp_isempty_ptr = 0;
	sppp_flush_ptr   = 0;
	return 0;
}

/*
 * Dispatcher function for the module (load/unload/stat).
 */
int sppp (struct lkm_table *lkmtp, int cmd, int ver)
{
	DISPATCH (lkmtp, cmd, ver, sppp_load, sppp_unload, nosys);
}
#endif /* SPPP_MODULE */

#endif /* SPPP_LOADABLE */
