#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "log.h"
#include "vty.h"
#include "stream.h"
#include "jhash.h"
#include "linklist.h"

#include "bgpd/bgp_attr.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_lsdb.h"
#include "bgpd/bgp_ls.h"






/***********************************************/
/* init a node descriptor*/
node_nlri_t* new_node_descriptor(void) 
{
    node_nlri_t* nn = XCALLOC(MTYPE_BGP_LSDB, sizeof(node_nlri_t));
    
    memset(nn, 0, sizeof(node_nlri_t));

    /* 这里 link 与 prefix_ip6 的 table 需要有对应的route_node_destory函数，以避免删除时的内存泄露 */
    nn->link_table = route_table_init();
    nn->prefix_ip6_table = route_table_init();

    return nn;
}

void delete_node_descriptor(node_nlri_t* nn) 
{
    /* 考虑线程安全性，nn->lock (To Do) */

    if(nn->link_table != NULL && nn->link_table->count) {
        /* node NLRI 下的 Link NLRI不为空， 需要先清空 */

        /* 删除route node */
        route_table_finish(nn->link_table);
    }
    if(nn->prefix_ip6_table != NULL && nn->prefix_ip6_table->count) {
        /* node NLRI 下的 Prefix_ip6 NLRI不为空， 需要先清空 */
        
        /* 删除route node */
        route_table_finish(nn->prefix_ip6_table);
    }

    XFREE(MTYPE_BGP_LSDB, nn);    
    
}

/* 考虑node NLRI删除时释放内存的安全性，记录对node NLRI的引用计数 */
void bgp_node_nlri_lock(node_nlri_t* nn) {
    nn->lock++;
}
void bgp_node_nlri_unlock(node_nlri_t* nn) {
    nn->lock--;
}

/* bgp_lsdb init*/
void bgp_lsdb_init(struct bgp_lsdb* lsdb) {
    lsdb->db = route_table_init();
}

struct bgp_lsdb *bgp_lsdb_new()
{
	struct bgp_lsdb *new;

	new = XCALLOC(MTYPE_BGP_LSDB, sizeof(struct bgp_lsdb));
	bgp_lsdb_init(new);

	return new;
}

/* bgp_lsdb clean */
// lsdb must be empty
void bgp_lsdb_cleanup(struct bgp_lsdb *lsdb)
{
	int i;
	assert(lsdb);
	assert(lsdb->total == 0);

	bgp_lsdb_delete_all(lsdb);
    route_table_finish(lsdb->db);
}

void bgp_lsdb_free(struct bgp_lsdb *lsdb)
{
	bgp_lsdb_cleanup(lsdb);
	XFREE(MTYPE_BGP_LSDB, lsdb);
}

/* Add nlri to lsdb, 假定 Link NLRI 与 Prefix NLRI 中的 LocalNode 对应 Node NLRI 已经被添加进LSDB */

/* set the key of lsdb hash table */
static void bgp_lsdb_key_set(uint32_t rid, bgp_lsdb_key_t* key)
{
    memset(&key, 0, sizeof(key));
    key.family = AF_INET;
    int len = sizeof(rid) > sizeof(key.prefix) ? sizeof(key.prefix) : sizeof(rid);
    memcpy((caddr_t)&key.prefix, (caddr_t)&rid, len);
    key.prefixlen = len * 8;
}
static void bgp_lsdb_node_key_set(node_nlri_t* nn, bgp_lsdb_key_t* key) 
{
    // node NLRI 以 Router ID 索引
    bgp_lsdb_key_set(nn->router_id, key);
}

static void bgp_lsdb_link_key_set(link_nlri_t* ln, bgp_lsdb_key_t* key)
{   
    // 同一node NLRI下的Link NLRI用Remote node ID 索引
    bgp_lsdb_key_set(ln->remote_node.router_id, key);
}

static void bgp_lsdb_prefix_ip6_key_set(prefix_ip6_nlri_t* p6n, bgp_lsdb_key_t* key)
{
    // 同一 node NLRI 下的 Prefix NLRI 以 Prefix 索引
    struct prefix_ipv6 ip6_prefix = p6n->prefix;
    assert(ip6_prefix->prefixlen != 0);

    memset(&key, 0, sizeof(key));
    int len = (ip6_prefix->prefixlen - 1) / 8 + 1;
    memcpy(key, ip6_prefix, len);
}

static void bgp_lsdb_add_node(struct bgp_lsdb* lsdb, node_nlri_t* nn) 
{   
    bgp_lsdb_key_t key;
    struct route_node *current;
    struct node_descriptor* old;

    bgp_lsdb_node_key_set(nn, key);
    current = route_node_get(lsdb->db, (struct prefix*)&key);
    old = current->info;
    bgp_node_nlri_lock(nn);

    nn->lsdb = lsdb;    // Set here ro NOT ???

    if(!old) {
        /* Need some checking */

        /* Update lsdb cnt*/
        lsdb->count++;
        lsdb->total++;

        /* Call the SPF calculate here */

    } else {
        /* check the sequence */
        if(old->sequence_num < nn->sequence_num) {
            /* Need some checking */

            /* Update node nlri */
            current->info = nn;
            nn->rn = current;

            /* Call the SPF calculate here */
        }
        else {
            /* current seq less or equal to the old, just delete the nn */
            delete_node_descriptor(nn);
            zlog_debug("[BGP LSDB] bgp_lsdb_add_node: the seq is less than or equal to the old one");
            
        }
        route_unlock_node(current);
        bgp_node_nlri_unlock(old);
    }

}

static void bgp_lsdb_add_link(struct bgp_lsdb* lsdb, struct link_nlri* ln) 
{   
    bgp_lsdb_key_t nn_key;
    bgp_lsdb_key_t ln_key;
    node_nlri_t* nn;
    struct route_node *local_node_rn;
    struct route_node *current;     // cur link NLRI route node
    struct link_nlri *old;

    if(ln->local_node == NULL) {
        zlog_debug("[BGP LSDB] bgp_lsdb_add_link: Unknown local node");
        /* maybe free ln ? */
        return;
    }

    // find the node NLRI
    bgp_lsdb_node_key_set(ln->local_node, nn_key);
    local_node_rn = route_node_lookup(lsdb->db, (struct prefix*)&nn_key);

    if(local_node_rn == NULL || local_node_rn->info == NULL) {
        zlog_debug("[BGP LSDB] bgp_lsdb_add_link: Cannot find the local node");
        /* maybe free ln ? */
        return;

    } else {
        nn = local_node_rn->info;
        bgp_lsdb_link_key_set(ln, &ln_key);
        current = route_node_get(nn->link_table, ln_key);
        old = current->info;

        /* check the sequence */
        if(old == NULL) {
            /* Need some checking */

            /* Update node nlri */
            ln->local_node->lsdb->total++;  // A new Link NLRI added

            /* Call the SPF calculate here */

        } else {
            /* NO sequence info in Link NLRI, just update and call SPF*/
            current->info = ln;
            ln->rn = current;

            /* Call the SPF calculate here */
        }

        // unlock
        route_unlock_node(current);
    }

}

static void bgp_lsdb_add_prefix_ip6(struct bgp_lsdb* lsdb, struct prefix_ip6_nlri* p6n) 
{   
    bgp_lsdb_key_t nn_key;
    bgp_lsdb_key_t p6n_key;
    node_nlri_t* nn;
    struct route_node *local_node_rn;
    struct route_node *current;     // cur link NLRI route node
    prefix_ip6_nlri_t *old;

    if(ln->local_node == NULL) {
        zlog_debug("[BGP LSDB] bgp_lsdb_add_prefix_ip6: Unknown local node");
        /* maybe free p6n ? */
        return;
    }

    /* find the local node */
    bgp_lsdb_node_key_set(p6n->local_node, &nn_key);
    local_node_rn = route_node_lookup(lsdb->db, (struct prefix*)&nn_key);

    if(local_node_rn == NULL || local_node_rn->info == NULL) {
        zlog_debug("[BGP LSDB] bgp_lsdb_add_prefix_ip6: Cannot find the local node");
        /* maybe free p6n ? */
        return;

    } else {
        nn = local_node_rn->info;
        bgp_lsdb_prefix_ip6_key_set(p6n, &p6n_key);
        current = route_node_get(nn->prefix_ip6_table, p6n_key);
        old = current->info;

        /* check the sequence */
        if(old == NULL) {
            /* Need some checking */

            /* Update node nlri */
            p6n->local_node->lsdb->total++;  // A new Link NLRI added

            /* Call the SPF calculate here */

        } else {
            /* NO sequence info in Link NLRI, just update and call SPF*/
            current->info = p6n;
            p6n->rn = current;

            /* Call the SPF calculate here */
        }

        // unlock
        route_unlock_node(current);
    }

}

struct bgp_lsdb* bgp_lsdb_add(struct bgp_lsdb* lsdb, int nlri_type, void* nlri) 
{
    if(lsdb == NULL) return NULL;
    if(nlri == NULL) {
        zlog_debug("bgp_lsdb_add empty nlri");
        return NULL;
    }

    int ret = 0;
    switch(nlri_type) {
        case BGP_LS_NODE_NLRI_TYPE:
            ret = bgp_lsdb_add_node(lsdb, nlri);
            break;
        case BGP_LS_LINK_NLRI_TYPE:
            ret = bgp_lsdb_add_link(lsdb, nlri);
            break;
        case BGP_LS_PREFIX_IP4_NLRI_TYPE:
            zlog_debug("Not support IPv4 prefix yet");
            ret = -1;
            break;
        case BGP_LS_PREFIX_IP6_NLRI_TYPE:
            ret = bgp_lsdb_add_prefix_ip6(lsdb, nlri);
            break;
        default :
            zlog_debug("Unknown type of bgp_ls_spf NLRI : %d", nlri_type);
            ret = -1;
            break;
    }

    return ret == -1 ? NULL : lsdb;
}















/************************************************/









/* Lock LS. */
struct bgp_ls *bgp_ls_lock(struct bgp_ls *ls)
{
	ls->lock++;
	return ls;
}

/* Unlock LS. */
void bgp_ls_unlock(struct bgp_ls **ls)
{
	/* This is sanity check. */
	if (!ls || !*ls)
		return;

	(*ls)->lock--;

	assert((*ls)->lock >= 0);

	if ((*ls)->lock == 0) {
		// bgp_ls_free(*ls);	/*new version*/
		*ls = NULL;
	}
}
/*Commented by CA: function is not used*/
// static unsigned int ls_hash_key_make(void *p)
// {
// 	const struct bgp_ls *link_state_attr = p;
// 	return jhash(link_state_attr, link_state_attr->header->nlri_length, 0);
// }

static uint32_t bgp_ls_get_local_id(struct bgp_ls* bl
{
    uint32_t id = 0;
    if((bl->node)) id = bl->node->local_node->value;
};
)

/* transform bgp_ls to key*/
static void bgp_lsdb_set_key(struct prefix_ipv6 *key, const void *value, int len)
{
	assert(key->prefixlen % 8 == 0);

	memcpy((caddr_t)&key->prefix + key->prefixlen / 8, (caddr_t)value, len);
	key->family = AF_INET6;
	key->prefixlen += len * 8;
}
// bgp_ls/NLRI结构内容不明确，待完善
static struct prefix_ipv6 ls_hash_key_make(void *p)
{
	const struct bgp_ls *link_state_attr = p;
	struct prefix_ipv6 key;


    return key;
}

void bgp_lsdb_init(struct bgp_lsdb *lsdb)
{
	int i;

	for (i = BGP_LS_MIN_NLRI_TYPE; i < BGP_LS_MIN_NLRI_TYPE; i++)
		lsdb->type[i].db = route_table_init();
}

struct bgp_lsdb *bgp_lsdb_new()
{
	struct bgp_lsdb *new;

	new = XCALLOC(MTYPE_BGP_LSDB, sizeof(struct bgp_lsdb));
	bgp_lsdb_init(new);

	return new;
}

/* lsdb must be empty */ 
void bgp_lsdb_cleanup(struct bgp_lsdb *lsdb)
{
	int i;
	assert(lsdb);
	assert(lsdb->total == 0);

	bgp_lsdb_delete_all(lsdb);

	for (i = BGP_LS_MIN_NLRI_TYPE; i < BGP_LS_MIN_NLRI_TYPE; i++)
		route_table_finish(lsdb->type[i].db);
}

void bgp_lsdb_free(struct bgp_lsdb *lsdb)
{
	bgp_lsdb_cleanup(lsdb);
	XFREE(MTYPE_BGP_LSDB, lsdb);
}

/*Add attribute into a buffer, return a common struct : struct bsg_ls*/
struct bgp_ls *ls_attr_node_set(struct attr *attr)
{
	struct bgp_ls *ls = NULL; /*new version*/

	if (attr) {
		ls = XCALLOC(MTYPE_BGP_LSDB, sizeof(struct bgp_ls));
        ls->link = NULL;
        ls->ipv6_prefix = NULL;
        ls->ipv4_prefix = NULL;
		/*--------mp_bgpls_nlri & mp_bgpls_nlri------------*/
		ls->header = &attr->mp_bgpls_nlri->header; //
		ls->node->proto_id = attr->mp_bgpls_nlri->ext_hdr.proto_id;
		ls->node->nlri_identifier =
			attr->mp_bgpls_nlri->ext_hdr.nlri_identifier;
		ls->node->local_node = attr->mp_bgpls_nlri->local_node;
		/*---------------link_state-------------------*/
		ls->node->mid = attr->mp_bgpls_nlri->mid;
		ls->node->nfb = &attr->link_state_attr->nfb; //
		ls->node->onp = attr->link_state_attr->onp;
		ls->node->nn = attr->link_state_attr->nn;
		ls->node->iiai = attr->link_state_attr->iiai;
		ls->node->i4ridofln = &attr->link_state_attr->i4ridofln; //
		ls->node->i6ridofln = &attr->link_state_attr->i6ridofln; //
		ls->node->i4ridofrn = &attr->link_state_attr->i4ridofrn; //
		ls->node->i6ridofrn = &attr->link_state_attr->i6ridofrn; //
	}
	return ls;
}

struct bgp_ls *ls_attr_link_set(struct attr *attr)
{
	struct bgp_ls *ls = NULL;
	if (attr) {
		ls = XCALLOC(MTYPE_BGP_LSDB, sizeof(struct bgp_ls));
        ls->node = NULL;
        ls->ipv6_prefix = NULL;
        ls->ipv4_prefix = NULL;
		/*--------mp_bgpls_nlri & mp_bgpls_nlri------------*/
		ls->header = &attr->mp_bgpls_nlri->header;
		ls->link->proto_id = attr->mp_bgpls_nlri->ext_hdr.proto_id;
		ls->link->nlri_identifier =
			attr->mp_bgpls_nlri->ext_hdr.nlri_identifier;
		ls->link->local_node = attr->mp_bgpls_nlri->local_node;
		ls->link->remote_node = attr->mp_bgpls_nlri->remote_node;
		ls->link->llri = &attr->mp_bgpls_nlri->llri;
		ls->link->i4ia = &attr->mp_bgpls_nlri->i4ia;
		ls->link->i4na = &attr->mp_bgpls_nlri->i4na;
		ls->link->i6ia = &attr->mp_bgpls_nlri->i6ia;
		ls->link->i6na = &attr->mp_bgpls_nlri->i6na;
		ls->link->mid = attr->mp_bgpls_nlri->mid;
		/*---------------link_state-------------------*/
		ls->link->i4ridofln = &attr->link_state_attr->i4ridofln;
		ls->link->i6ridofln = &attr->link_state_attr->i6ridofln;
		ls->link->i4ridofrn = &attr->link_state_attr->i4ridofrn;
		ls->link->i6ridofrn = &attr->link_state_attr->i6ridofrn;
		ls->link->agc = &attr->link_state_attr->agc;
		ls->link->mlb = &attr->link_state_attr->mlb;
		ls->link->mrlb = &attr->link_state_attr->mrlb;
		ls->link->urb = &attr->link_state_attr->urb;
		ls->link->tdm = &attr->link_state_attr->tdm;
		ls->link->lpt = &attr->link_state_attr->lpt;
		ls->link->mpm = &attr->link_state_attr->mpm;
		ls->link->igpm = attr->link_state_attr->igpm;
		ls->link->srlg = attr->link_state_attr->srlg;
		ls->link->ola = attr->link_state_attr->ola;
		ls->link->lna = attr->link_state_attr->lna;
	}
	return ls;
}

struct bgp_ls *ls_attr_ipv4_prefix_set(struct attr *attr)
{
	struct bgp_ls *ls = NULL;
	if (attr) {
		ls = XCALLOC(MTYPE_BGP_LSDB, sizeof(struct bgp_ls));
        ls->node = NULL;
        ls->link = NULL;
        ls->ipv6_prefix = NULL;
		/*--------mp_bgpls_nlri & mp_bgpls_nlri------------*/
		ls->ipv4_prefix->header = &attr->mp_bgpls_nlri->header;
		ls->ipv4_prefix->proto_id =
			attr->mp_bgpls_nlri->ext_hdr.proto_id;
		ls->node->nlri_identifier =
			attr->mp_bgpls_nlri->ext_hdr.nlri_identifier;
		ls->ipv4_prefix->local_node = attr->mp_bgpls_nlri->local_node;
		ls->ipv4_prefix->mid = attr->mp_bgpls_nlri->mid;
		ls->ipv4_prefix->ort = &attr->mp_bgpls_nlri->ort;
		ls->ipv4_prefix->ipreach = attr->mp_bgpls_nlri->ipreach;
		/*---------------link_state-------------------*/
		ls->ipv4_prefix->ifl = &attr->link_state_attr->ifl;
		ls->ipv4_prefix->rt = attr->link_state_attr->rt;
		ls->ipv4_prefix->et = attr->link_state_attr->et;
		ls->ipv4_prefix->pm = &attr->link_state_attr->pm;
		ls->ipv4_prefix->ofa = &attr->link_state_attr->ofa;
		ls->ipv4_prefix->opa = attr->link_state_attr->opa;
	}
	return ls;
}

struct bgp_ls *ls_attr_ipv6_prefix_set(struct attr *attr)
{
	struct bgp_ls *ls = NULL;
	if (attr) {
		ls = XCALLOC(MTYPE_BGP_LSDB, sizeof(struct bgp_ls));
        ls->node = NULL;
        ls->link = NULL;
        ls->ipv4_prefix = NULL;
		/*--------mp_bgpls_nlri & mp_bgpls_nlri------------*/
		ls->ipv6_prefix->header = &attr->mp_bgpls_nlri->header;
		ls->ipv6_prefix->proto_id =
			attr->mp_bgpls_nlri->ext_hdr.proto_id;
		ls->ipv6_prefix->nlri_identifier =
			attr->mp_bgpls_nlri->ext_hdr.nlri_identifier;
		ls->ipv6_prefix->local_node = attr->mp_bgpls_nlri->local_node;
		ls->ipv6_prefix->mid = attr->mp_bgpls_nlri->mid;
		ls->ipv6_prefix->ort = &attr->mp_bgpls_nlri->ort;
		ls->ipv6_prefix->ipreach = attr->mp_bgpls_nlri->ipreach;
		/*--------------------link_state--------------------*/
		ls->ipv6_prefix->ifl = &attr->link_state_attr->ifl;
		ls->ipv6_prefix->rt = attr->link_state_attr->rt;
		ls->ipv6_prefix->et = attr->link_state_attr->et;
		ls->ipv6_prefix->pm = &attr->link_state_attr->pm;
		ls->ipv6_prefix->ofa = &attr->link_state_attr->ofa;
		ls->ipv6_prefix->opa = attr->link_state_attr->opa;
	}
	return ls;
}

struct bgp_ls *ls_attr_set(struct attr *attr, uint16_t nlri_type)
{
	struct bgp_ls *ls;
    // switch nlri type by attr

    switch(nlri_type) {
        case LINK_STATE_NODE_NLRI:
            ls = ls_attr_node_set(attr);
            break;
        case LINK_STATE_LINK_NLRI:
            ls = ls_attr_link_set(attr);
            break;
        case LINK_STATE_IPV4_TOPOLOGY_PREFIX_NLRI:
            ls = ls_attr_ipv4_prefix_set(attr);
            break;
        case LINK_STATE_IPV6_TOPOLOGY_PREFIX_NLRI:
            ls = ls_attr_ipv6_prefix_set(attr);
            break;
        default :
            ls = NULL;  // something error;
            break;
    }

	return ls;
}

static void bgp_lsdb_delete_entry(struct bgp_lsdb *lsdb, struct route_node *rn)
{

	struct bgp_ls *ls = rn->info;

	if (!ls)
		return;

	assert(rn->table == lsdb->type[ls->header->nlri_type].db);
	lsdb->type[ls->header->nlri_type].count--;
	lsdb->total--;
	rn->info = NULL;
	route_unlock_node(rn);
	bgp_ls_unlock(&ls); /* lsdb */
	return;
}

/* Add new LS to lsdb. */
struct bgp_lsdb *bgp_lsdb_add(struct bgp_lsdb *lsdb, struct bgp_ls *ls)
{
	struct route_table *table;
    bgp_lsdb_key_t *key;
	// struct attr attr;
	struct route_node *rn;
	int i;
	for (i = BGP_LS_MIN_NLRI_TYPE; i <= BGP_LS_MAX_NLRI_TYPE; i++) {
		// table = lsdb->type[ls->header->nlri_type].db;
		table = lsdb->type[i].db;
        key = ls_hash_key_make(ls);
		rn = route_node_get(table, key); //

		/* nothing to do? 找到了相同的ls */
		if (rn->info && rn->info == ls) {
			route_unlock_node(rn);
			return lsdb;
		}

		/* purge old entry? */
		if (rn->info)
			bgp_lsdb_delete_entry(lsdb, rn);

		lsdb->type[ls->header->nlri_type].count++;
		lsdb->total++;
		rn->info = bgp_ls_lock(ls); /* add to lsdb， why lock??? */
	}
	return lsdb;
}

void bgp_lsdb_delete(struct bgp_lsdb *lsdb, struct bgp_ls *ls)
{
	struct route_table *table;
    bgp_lsdb_key_t *key;
	struct route_node *rn;

	if (!lsdb) {
		zlog_warn("%s: Called with NULL LSDB", __func__);
		if (ls)
			zlog_warn("LSA[Type%d:%d]: LS %d, lsa->lsdb %d", 0, 0,
				  0, 0);

		return;
	}

	if (!ls) {
		zlog_warn("%s: Called with NULL LS", __func__);
		return;
	}

	assert(ls->header->nlri_type < BGP_LS_MAX_NLRI_TYPE);
	table = lsdb->type[ls->header->nlri_type].db;
    key = ls_hash_key_make(ls);
	// ls_attr_set (&attr, ls);
	if ((rn = route_node_lookup(table, key))) {
		if (rn->info == ls)
			bgp_lsdb_delete_entry(lsdb, rn);
		route_unlock_node(rn); /* route_node_lookup */
	}
}

void bgp_lsdb_delete_all(struct bgp_lsdb *lsdb)
{
	struct route_table *table;
	struct route_node *rn;
	int i;

	for (i = BGP_LS_MIN_NLRI_TYPE; i < BGP_LS_MAX_NLRI_TYPE; i++) {
		table = lsdb->type[i].db;
		for (rn = route_top(table); rn; rn = route_next(rn))
			if (rn->info != NULL)
				bgp_lsdb_delete_entry(lsdb, rn);
	}
}

struct bgp_ls *bgp_lsdb_lookup(struct bgp_lsdb *lsdb, struct bgp_ls *ls)
{
	struct route_table *table;
    bgp_lsdb_key_t *key;
	// struct attr attr;
	struct route_node *rn;
	struct bgp_ls *find;

	table = lsdb->type[ls->header->nlri_type].db;
	key = ls_hash_key_make(ls);
	rn = route_node_lookup(table, key);
	if (rn) {
		find = rn->info;
		route_unlock_node(rn);
		return find;
	}
	return NULL;
}

// 怎么NLRI的type, id, adv_router???
struct bgp_ls *bgp_lsdb_lookup_by_id(struct bgp_lsdb *lsdb, uint8_t type,
				     struct in_addr id,
				     struct in_addr adv_router)
{
	struct route_table *table;
	struct attr attr;
	struct route_node *rn;
	struct bgp_ls *find;

	table = lsdb->type[type].db;

	memset(&attr, 0, sizeof(struct attr));
	// attr.family = 0;
	// attr.prefixlen = 64;
	// attr.id = id;
	// attr.adv_router = adv_router;

	rn = route_node_lookup(table, (struct prefix *)&attr);
	if (rn) {
		find = rn->info;
		route_unlock_node(rn);
		return find;
	}

	return NULL;
}

struct bgp_ls *bgp_lsdb_lookup_by_id_next(struct bgp_lsdb *lsdb, uint8_t type,
					  struct in_addr id,
					  struct in_addr adv_router, int first)
{
	struct route_table *table;
	struct bgp_ls ls;
	struct route_node *rn;
	struct bgp_ls *find;

	table = lsdb->type[type].db;

	memset(&ls, 0, sizeof(struct bgp_ls));
	/*
	  attr.family = 0;
	  attr.prefixlen = 64;
	  attr.id = id;
	  attr.adv_router = adv_router;
	 */

	if (first)
		rn = route_top(table);
	else {
		if ((rn = route_node_lookup(table, (struct prefix *)&ls))
		    == NULL)
			return NULL;
		rn = route_next(rn);
	}

	for (; rn; rn = route_next(rn))
		if (rn->info)
			break;

	if (rn && rn->info) {
		find = rn->info;
		route_unlock_node(rn);
		return find;
	}
	return NULL;
}

unsigned long bgp_lsdb_count_all(struct bgp_lsdb *lsdb)
{
	return lsdb->total;
}

unsigned long bgp_lsdb_count(struct bgp_lsdb *lsdb, int type)
{
	return lsdb->type[type].count;
}

void bgp_lsdb_delete_entry(struct bgp_lsdb *lsdb, struct route_node *rn)
{
	struct bgp_ls *ls = rn->info;

	if (!ls)
		return;

	lsdb->total--;
	rn->info = NULL;
	route_unlock_node(rn);

	return;
}

// unsigned long bgp_lsdb_count_all(struct bgp_lsdb *lsdb)
//{
//	return lsdb->total;
//}
//
// unsigned long bgp_lsdb_count(struct bgp_lsdb *lsdb, int type)
//{
//	return lsdb->type[type].count;
//}

/*
unsigned long
bgp_lsdb_count_self (struct bgp_lsdb *lsdb, int type)
{
  return lsdb->type[type].count_self;
}
*/

unsigned int bgp_lsdb_checksum(struct bgp_lsdb *lsdb, int type)
{
	return lsdb->type[type].checksum;
}

unsigned long bgp_lsdb_isempty(struct bgp_lsdb *lsdb)
{
	return (lsdb->total == 0);
}