#include "ircd.h"

char *ws_skip(s)
char *s;
{
	while (*s && isspace(*s))
		s++;
	return s;
}

char *ws_cut(s)
char *s;
{
	while (*s && !isspace(*s))
		s++;
	if (!*s) return s;
	*s++ = '\0';
	return ws_skip(s);
}

int u_msg_parse(msg, s)
struct u_msg *msg;
char *s;
{
	int i;
	char *p;

	s = ws_skip(s);
	if (!*s) return -1;

	if (*s == ':') {
		msg->source = ++s;
		s = ws_cut(s);
		if (!*s) return -1;
	} else {
		msg->source = NULL;
	}

	msg->command = s;
	s = ws_cut(s);

	for (msg->argc=0; msg->argc<U_MSG_MAXARGS && *s;) {
		if (*s == ':') {
			msg->argv[msg->argc++] = ++s;
			break;
		}

		msg->argv[msg->argc++] = s;
		s = ws_cut(s);
	}

	for (p=msg->command; *p; p++)
		*p = toupper(*p);

	return 0;
}


/* let bss initialize to zero */
static struct u_hash commands[CTX_MAX];

int reg_one_real(cmd, ctx)
struct u_cmd *cmd;
int ctx;
{
	if (u_hash_get(&commands[ctx], cmd->name))
		return -1;

	u_hash_set(&commands[ctx], cmd->name, cmd);
	return 0;
}

int reg_one(cmd)
struct u_cmd *cmd;
{
	int i, err;

	if (cmd->ctx >= 0)
		return reg_one_real(cmd, cmd->ctx);

	for (i=0; i<CTX_MAX; i++) {
		if ((err = reg_one_real(cmd, i)) < 0)
			return err;
	}
	return 0;
}

int u_cmds_reg(cmds)
struct u_cmd *cmds;
{
	int err;
	for (; cmds->name[0]; cmds++) {
		if ((err = reg_one(cmds)) < 0)
			return err;
	}
	return 0;
}

/* TODO: these are all starting to look the same... */

void u_cmd_invoke(conn, msg)
struct u_conn *conn;
struct u_msg *msg;
{
	struct u_cmd *cmd;

	cmd = u_hash_get(&commands[conn->ctx], msg->command);

	/* TODO: command not found */
	if (!cmd)
		return;

	/* TODO: not enough args */
	if (msg->argc < cmd->nargs)
		return;

	cmd->cb(conn, msg);
}
