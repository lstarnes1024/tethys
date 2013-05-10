#include "ircd.h"

#define LEFT 0
#define RIGHT 1

struct u_map_n {
	void *key, *data;
	enum u_map_color { RED, BLACK } color;
	u_map_n *parent, *child[2];
};

static void n_key(map, n, k) u_map *map; u_map_n *n; void *k;
{
	if (map->flags & MAP_STRING_KEYS) {
		if (n->key != NULL)
			free(n->key);

		if (k != NULL) {
			n->key = u_strdup(k); /* ;_; */
			return;
		}
	}

	n->key = k;
}

static int n_cmp(map, k1, k2) u_map *map; void *k1, *k2;
{
	if (map->flags & MAP_STRING_KEYS)
		return strcmp((char*)k1, (char*)k2);

	return (long)k1 - (long)k2;
}

static u_map_n *u_map_n_new(map, key, data, color)
u_map *map; void *key, *data;
{
	u_map_n *n;

	n = malloc(sizeof(*n));
	n->key = NULL;
	n_key(map, n, key);
	n->data = data;
	n->color = color;

	n->parent = NULL;
	n->child[0] = n->child[1] = NULL;

	return n;
}

static void u_map_n_del(map, n) u_map *map; u_map_n *n;
{
	if ((map->flags & MAP_STRING_KEYS) && n->key)
		free(n->key);
	free(n);
}

u_map *u_map_new(string_keys)
{
	u_map *map;

	map = malloc(sizeof(*map));
	if (map == NULL)
		return NULL;

	map->flags = string_keys ? MAP_STRING_KEYS : 0;
	map->root = NULL;
	map->size = 0;

	return map;
}

void u_map_free(map) u_map *map;
{
	u_map_n *n, *tn;

	for (n=map->root; n; ) {
		if (n->child[LEFT]) {
			n = n->child[LEFT];
			continue;
		}

		if (n->child[RIGHT]) {
			n = n->child[RIGHT];
			continue;
		}

		tn = n->parent;
		if (tn != NULL)
			tn->child[n == tn->child[LEFT] ? LEFT : RIGHT] = NULL;
		u_map_n_del(map, n);
		n = tn;
	}

	free(map);
}

static u_map_n *dumb_fetch();
static void rb_delete();

static void clear_pending(map) u_map *map;
{
	u_list_init(&map->pending);
}

static void delete_pending(map) u_map *map;
{
	u_list *cur, *tn;
	u_map_n *n;

	U_LIST_EACH_SAFE(cur, tn, &map->pending) {
		n = dumb_fetch(map, cur->data);
		u_log(LG_FINE, "DEL PENDING %p (n=%p)", cur->data, n);
		if (n != NULL)
			rb_delete(map, n);
		u_list_del_n(&map->pending, cur);
	}
}

static void add_pending(map, n) u_map *map; u_map_n *n;
{
	u_log(LG_FINE, "ADD PENDING %p (n=%p)", n->key, n);
	u_list_add(&map->pending, n->key);
}

void u_map_each(map, cb, priv) u_map *map; void (*cb)(); void *priv;
{
	u_map_n *cur;
	int idx;

	if ((cur = map->root) == NULL)
		return;

	map->flags |= MAP_TRAVERSING;
	clear_pending(map);

try_left:
	if (cur->child[LEFT] != NULL) {
		cur = cur->child[LEFT];
		goto try_left;
	}

loop_top:
	cb(map, cur->key, cur->data, priv);

	if (cur->child[RIGHT] != NULL) {
		cur = cur->child[RIGHT];
		goto try_left;
	}

	for (;;) {
		if (cur->parent == NULL)
			break;
		idx = cur->parent->child[LEFT] == cur ? LEFT : RIGHT;
		cur = cur->parent;
		if (idx == LEFT)
			goto loop_top;
	}

	map->flags &= ~MAP_TRAVERSING;
	delete_pending(map);
}

/* dumb functions are just standard binary search tree operations that
   don't pay attention to the colors of the nodes */

static u_map_n *dumb_fetch(map, key) u_map *map; void *key;
{
	u_map_n *n = map->root;

	while (n != NULL) {
		if (!n_cmp(map, n->key, key))
			break;
		n = n->child[n_cmp(map, n->key, key) < 0];
	}

	return n;
}

static void dumb_insert(map, n) u_map *map; u_map_n *n;
{
	u_map_n *cur;
	int idx;

	if (map->root == NULL) {
		map->root = n;
		map->root->parent = NULL;
		return;
	}

	cur = map->root;

	for (;;) {
		idx = n_cmp(map, cur->key, n->key) < 0 ? RIGHT : LEFT;
		if (cur->child[idx] == NULL) {
			cur->child[idx] = n;
			n->parent = cur;
			break;
		}
		cur = cur->child[idx];
	}
}

static u_map_n *leftmost_subchild(n) u_map_n *n;
{
	while (n && n->child[LEFT])
		n = n->child[LEFT];
	return n;
}

static u_map_n *dumb_delete(map, n) u_map *map; u_map_n *n;
{
	int idx;
	u_map_n *tgt;

	if (n->child[LEFT] == NULL && n->child[RIGHT] == NULL) {
		if (n->parent == NULL) {
			/* we are the sole node, the root */
			map->root = NULL;
			return n;
		}

		idx = n->parent->child[LEFT] == n ? LEFT : RIGHT;
		n->parent->child[idx] = NULL;
		return n;

	} else if (n->child[LEFT] == NULL || n->child[RIGHT] == NULL) {
		/* tgt = the non-null child */
		tgt = n->child[n->child[LEFT] == NULL ? RIGHT : LEFT];

		if (n->parent == NULL) {
			map->root = tgt;
			tgt->parent = NULL;
			return n;
		}

		idx = n->parent->child[LEFT] == n ? LEFT : RIGHT;

		n->parent->child[idx] = tgt;
		tgt->parent = n->parent;
		return n;
	}

	/* else, both non-null */

	/* the successor will have at most one non-null child, so this
	   will only recurse once */
	tgt = leftmost_subchild(n->child[RIGHT]);
	n->data = tgt->data;
	/* we don't use n_key here, since this is faster */
	if ((map->flags & MAP_STRING_KEYS) && n->key)
		free(n->key);
	n->key = tgt->key;
	tgt->key = NULL;
	return dumb_delete(map, tgt);
}

static void rb_delete(map, n) u_map *map; u_map_n *n;
{
	if (map->flags & MAP_STRING_KEYS)
		u_log(LG_FINE, "MAP: %p RB-DEL %s", map, n->key);
	else
		u_log(LG_FINE, "MAP: %p RB-DEL %p", map, n->key);

	n = dumb_delete(map, n);

	/* TODO: rb cases */

	u_map_n_del(map, n);
}

void *u_map_get(map, key) u_map *map; void *key;
{
	u_map_n *n = dumb_fetch(map, key);
	return n == NULL ? NULL : n->data;
}

void u_map_set(map, key, data) u_map *map; void *key, *data;
{
	u_map_n *n = dumb_fetch(map, key);

	if (map->flags & MAP_TRAVERSING)
		abort();

	if (n != NULL) {
		n->data = data;
		return;
	}

	map->size++;

	n = u_map_n_new(map, key, data, RED);
	dumb_insert(map, n);

	/* TODO: rb cases */
}

void *u_map_del(map, key) u_map *map; void *key;
{
	u_map_n *n = dumb_fetch(map, key);
	void *data;

	if (n == NULL)
		return NULL;

	if (map->flags & MAP_STRING_KEYS)
		u_log(LG_FINE, "MAP: %p DEL %s", map, n->key);
	else
		u_log(LG_FINE, "MAP: %p DEL %p", map, n->key);

	/* we decrement size here, even if the deletion doesn't actually
	   happen, since we consider the node to have been deleted when
	   u_map_del is called. */
	map->size--;

	data = n->data;
	n->data = NULL;

	if (map->flags & MAP_TRAVERSING)
		add_pending(map, n);
	else
		rb_delete(map, n);

	return data;
}

static void indent(depth)
{
	while (depth-->0)
		printf("  ");
}

static void map_dump_real(map, n, depth) u_map *map; u_map_n *n;
{
	if (n == NULL) {
		printf("*");
		return;
	}

/*
	too many compiler warnings to bother with this...
	if (map->flags & MAP_STRING_KEYS) {
		printf("\e[%sm%s=%d\e[0m[", n->color == RED ? "31;1" : "36;1",
		       (char*)n->key, (long)n->data);
	} else {
		printf("\e[%sm%d=%d\e[0m[", n->color == RED ? "31;1" : "36;1",
		       (long)n->key, (long)n->data);
	}
*/

	if (n->child[LEFT] == NULL && n->child[RIGHT] == NULL) {
		printf("]");
		return;
	}
	printf("\n");
	indent(depth);
	map_dump_real(map, n->child[LEFT], depth + 1);
	printf(",\n");
	indent(depth);
	map_dump_real(map, n->child[RIGHT], depth + 1);
	printf("]");
}

void u_map_dump(map) u_map *map;
{
	map_dump_real(map, map->root, 1);
	printf("\n\n");
}
