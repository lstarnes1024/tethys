/* ircd-micro, dns.h -- domain name lookups
   Copyright (C) 2013 Alex Iadicicco

   This file is protected under the terms contained
   in the COPYING file in the project root */

#ifndef __INC_DNS_H__
#define __INC_DNS_H__

/* callback statuses */
#define DNS_OKAY      0   /* request was okay, res is valid */
#define DNS_NXDOMAIN  1   /* nonexistent domain */
#define DNS_TIMEOUT   2   /* request timed out */
#define DNS_INVALID   3   /* invalid request */
#define DNS_TOOLONG   4   /* request too long */

extern void u_dns_use_io(); /* struct u_io* */

/* cb(status, res, priv) */
extern void u_dns(); /* char*, void (*cb)(), void *priv */
extern void u_rdns(); /* char*, void (*cb)(), void *priv */

extern int init_dns();

#endif
