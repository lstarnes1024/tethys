/* Tethys, core/who -- WHO command
   Copyright (C) 2014 Alex Iadicicco

   This file is protected under the terms contained
   in the COPYING file in the project root */

#include "ircd.h"

struct who_query {
	bool flags[256];
	bool whox;
	const char * type;
};

static void who_append_fmt (char *buf, size_t size, size_t *pos, const char *fmt, ...) {
	va_list ap;
	size_t max, used;

	max = *pos >= size ? 0 : size - *pos;
	va_start(ap, fmt);
	used = vsnf(FMT_USER, buf + *pos, size, fmt, ap);
	va_end(ap);
	*pos += used;
}

static void who_parse_params (struct who_query *q, const char *params) {
	char *s;

	memset(&q->flags, 0, sizeof q->flags);
	q->whox = false;
	q->type = NULL;

	if (!params)
		return;

	s = strchr(params, '%');
	if (!s) /* no % found, so not WHOX */
		return;

	s++; /* skip % */
	q->whox = true;

	for (;*s != '\0'; s++) {
		if (*s == ',') {  /* reached separator */
			q->type = ++s;
			break;
		}
		q->flags[*s] = true;
	}
}

static void who_reply(u_sourceinfo *si, u_user *u, u_chan *c, u_chanuser *cu,
	struct who_query *q)
{
	u_server *sv;
	char *s, statbuf[6];
	mowgli_node_t *n;

	if (c == NULL) {
		/* oh god this is so bad */
		u_map_each_state state;
		U_MAP_EACH(&state, u->channels, &c, NULL)
			break;
		cu = NULL;
	}

	if (c != NULL && cu == NULL)
		cu = u_chan_user_find(c, u);

	if (cu == NULL) /* this is an error */
		c = NULL;

	s = statbuf;
	*s++ = IS_AWAY(u) ? 'G' : 'H';
	if (IS_OPER(u))
		*s++ = '*';
	MOWGLI_LIST_FOREACH(n, cu_pfx_list.head) {
		u_cu_pfx *cs = n->data;
		if (cu && (cu->flags & cs->mask))
			*s++ = cs->prefix;
	}
	*s = '\0';

	/* handle standard WHO query */
	if (!q->whox) {
		u_src_num(si, RPL_WHOREPLY, c, u->ident, u->host, u->sv->name,
		          u->nick, statbuf, 0, u->gecos);
	} else { /* handle WHOX query */
		char buf[BUFSIZE];
		size_t pos = 0;
		if (q->flags['t'])
			who_append_fmt(buf, sizeof buf, &pos, "%s ", q->type);
		if (q->flags['c'])
			who_append_fmt(buf, sizeof buf, &pos, "%C ", c);
		if (q->flags['u'])
			who_append_fmt(buf, sizeof buf, &pos, "%s ", u->nick);
		if (q->flags['i']) {
			/* XXX there needs to be a better way determine if the
			 * source can view a user's real IP
			 */
			if (!(u->mode & UMODE_CLOAKED) || (si->u && IS_OPER(si->u)))
				who_append_fmt(buf, sizeof buf, &pos, "%s ", u->ip);
			else
				who_append_fmt(buf, sizeof buf, &pos, "255.255.255.255 ");
		}
		if (q->flags['h'])
			who_append_fmt(buf, sizeof buf, &pos, "%s ", u->host);
		if (q->flags['s'])
			who_append_fmt(buf, sizeof buf, &pos, "%s ", u->sv->name);
		if (q->flags['n'])
			who_append_fmt(buf, sizeof buf, &pos, "%s ", u->nick);
		if (q->flags['f'])
			who_append_fmt(buf, sizeof buf, &pos, "%s ", statbuf);
		if (q->flags['d'])
			who_append_fmt(buf, sizeof buf, &pos, "%d ", u->sv->hops);
		if (q->flags['l'])
			who_append_fmt(buf, sizeof buf, &pos, "%d ", 0); /* TODO display idle time */
		if (q->flags['a'])
			who_append_fmt(buf, sizeof buf, &pos, "%s ", IS_LOGGED_IN(u) ? u->acct : "0");
		if (q->flags['r'])
			who_append_fmt(buf, sizeof buf, &pos, ":%s", u->gecos);

		u_src_num(si, RPL_WHOSPCRPL, buf);
	}
}

static int c_lu_who(u_sourceinfo *si, u_msg *msg)
{
	u_user *u;
	u_chan *c = NULL;
	u_chanuser *cu;
	struct who_query q;
	char *name = msg->argv[0];
	char *params = (msg->argc > 1) ? msg->argv[1] : NULL;

	/* Parse WHOX flags */
	who_parse_params (&q, params);

	if (strchr(CHANTYPES, *name)) {
		u_map_each_state state;
		bool visible_only = false;

		if ((c = u_chan_get(name)) == NULL)
			goto end;

		if ((cu = u_chan_user_find(c, si->u)) == NULL) {
			if (c->mode & CMODE_SECRET)
				goto end;
			visible_only = true;
		}

		U_MAP_EACH(&state, c->members, &u, &cu) {
			if (visible_only && (u->mode & UMODE_INVISIBLE))
				continue;
			who_reply(si, u, c, cu, &q);
		}
	} else {
		if ((u = u_user_by_nick(name)) == NULL)
			goto end;

		who_reply(si, u, NULL, NULL, &q);
	}

end:
	u_src_num(si, RPL_ENDOFWHO, name);
	return 0;
}

static u_cmd who_cmdtab[] = {
	{ "WHO", SRC_LOCAL_USER, c_lu_who, 1 },
	{ }
};

TETHYS_MODULE_V1(
	"core/who", "Alex Iadicicco", "WHO command",
	NULL, NULL, who_cmdtab);
