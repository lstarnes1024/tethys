#ifndef __INC_CONN_H__
#define __INC_CONN_H__

#define U_CONN_OBUFSIZE 2048

#define U_CONN_CLOSING 0x0001

/* connection contexts. used for command processing */
#define CTX_UNREG       0
#define CTX_USER        1
#define CTX_SERVER      2
#define CTX_MAX         3

struct u_conn {
	unsigned flags;
	struct u_io_fd *sock;
	struct u_linebuf ibuf;
	char *obuf;
	int obuflen, obufsize;
	void *priv;
	int ctx;
};

struct u_conn_origin {
	struct u_io_fd *sock;
	void (*cb)(); /* u_io_fd* */
};

extern void u_conn_init(); /* u_conn* */
extern void u_conn_obufsize(); /* u_conn*, int obufsize */

/* u_io*, u_long addr, u_short port, void (*cb)(); */
extern struct u_conn_origin *u_conn_origin_create();

#endif
