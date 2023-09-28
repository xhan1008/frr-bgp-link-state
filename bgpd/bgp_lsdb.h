#ifndef _BGP_LS_LSDB_H
#define _BGP_LS_LSDB_H
#define BGP_LS_MIN_NLRI_TYPE 1
#define BGP_LS_MAX_NLRI_TYPE 4

#define BGP_LS_NODE_NLRI_TYPE 1
#define BGP_LS_LINK_NLRI_TYPE 2
#define BGP_LS_PREFIX_IP4_NLRI_TYPE 3
#define BGP_LS_PREFIX_IP6_NLRI_TYPE 4

#include"table.h"


/************************** kjwl begin********************************/

/* The key of bgp_lsdb hash table*/
typedef struct prefix bgp_lsdb_key_t;

struct bgp_lsdb 
{
    struct route_table *db;
    unsigned long count;        // num of node nlri
	unsigned long total;        // num of nlri
};

typedef struct node_descriptor
{
    uint32_t AS_num;
    uint32_t router_id;
    

    /* draft-ietf-lsvr-bgp-spf-28 6.1: seq包含在local Node中？*/
    uint64_t sequence_num;  
} node_descriptor_t;

typedef struct node_nlri
{
    node_descriptor_t local_node;

    uint64_t sequence_num;  // sequence_num 和 (node, link)之间的对应关系？？？ 
    uint8_t spf_capacity;
    uint8_t spf_state;

    /* All of reference count, also lock to remove. */
	int lock;

    struct route_table *link_table;         // make key by remote node
    struct route_table *prefix_ip6_table;   // make key by prefix

    struct route_node* rn;
    struct bgp_lsdb* lsdb;
}node_nlri_t;

typedef struct link_nlri 
{
    uint8_t spf_state;
    uint32_t metric;
    uint64_t sequence_num;

    /* All of reference count, also lock to remove. */
	int lock;

    /* draft-ietf-lsvr-bgp-spf-28 6.1
       Link or Prefix NLRI is no longer being advertised
       by the local node, the NLRI is withdrawn. */
    node_descriptor_t local_node;
    node_descriptor_t remote_node;

    /* link descriptor */
    struct prefix_ipv6 local_prefix;
    struct prefix_ipv6 remote_prefix;

    struct route_node* rn;
}link_nlri_t;

typedef struct prefix_ip6_nlri 
{
    uint32_t metric;
    struct prefix_ipv6 prefix;

    /* All of reference count, also lock to remove. */
	int lock;
    
    node_descriptor_t local_node;
    struct route_node* rn;
}prefix_ip6_nlri_t;

#define NLRI_SEQ(x) (x->local_node.sequence_num)

/* route table delegate function */

void *bgp_lsdb_node_rn_delete(route_table_delegate_t *delegate,
			struct route_table *table, struct route_node *node)
void *bgp_lsdb_link_rn_delete(route_table_delegate_t *delegate,
			struct route_table *table, struct route_node *node)
void *bgp_lsdb_prefix6_rn_delete(route_table_delegate_t *delegate,
			struct route_table *table, struct route_node *node)



/* lsdb function*/

extern struct bgp_lsdb *bgp_lsdb_create(void);
extern void bgp_lsdb_delete_entry(struct bgp_lsdb* lsdb, struct route_node* rn);
extern void bgp_lsdb_delete_all(struct bgp_lsdb* lsdb);


/* nlri */

static void delete_node_nlri(node_nlri_t* nn);
extern node_nlri_t* new_node_nlri(void);
extern node_nlri_t* bgp_node_nlri_lock(node_nlri_t* nn);
extern void bgp_node_nlri_unlock(node_nlri_t** nn);

static void delete_link_nlri(link_nlri_t** ln);
extern node_nlri_t* new_link_nlri(void);
extern link_nlri_t* bgp_link_nlri_lock(link_nlri_t* ln);
extern void bgp_link_nlri_unlock(link_nlri_t** ln);

static void delete_prefix_ip6_nlri(prefix_ip6_nlri_t** p6n);
extern node_nlri_t* new_prefix_ip6_nlri(void);
extern link_nlri_t* bgp_prefix_ip6_nlri_lock(prefix_ip6_nlri_t* p6n);
extern void bgp_prefix_ip6_nlri_unlock(prefix_ip6_nlri_t** p6n);

/* Add func */

static void bgp_lsdb_add_node(struct bgp_lsdb* lsdb, node_nlri_t* nn);
static void bgp_lsdb_add_link(struct bgp_lsdb* lsdb, struct link_nlri* ln);
static void bgp_lsdb_add_prefix_ip6(struct bgp_lsdb* lsdb, struct prefix_ip6_nlri* p6n);
extern struct bgp_lsdb* bgp_lsdb_add(struct bgp_lsdb* lsdb, int nlri_type, void* nlri) ;


/* Delete func */

static void bgp_lsdb_delete_node(struct bgp_lsdb* lsdb, node_nlri_t* nd);
static void bgp_lsdb_delete_link(struct bgp_lsdb* lsdb, link_nlri_t* ln);
static void bgp_lsdb_delete_prefix_ip6(struct bgp_lsdb* lsdb, prefix_ip6_nlri_t*);
extern struct bgp_lsdb* bgp_lsdb_delete(struct bgp_lsdb* lsdb, int nlri_type, void* nlri);


/* Lookup */

static void bgp_lsdb_lookup_node(struct route_table* table, bgp_lsdb_key_t* nd);
static void bgp_lsdb_lookup_link(struct route_table* lsdb, bgp_lsdb_key_t* ln);
static void bgp_lsdb_lookup_prefix_ip6(struct route_table* lsdb, bgp_lsdb_key_t* p6l);
extern void* bgp_lsdb_lookup(struct bgp_lsdb* lsdb, bgp_lsdb_key_t* key);

/************************** kjwl end ********************************/





/* BGP LSDB structure. */
// struct bgp_lsdb {
// 	struct {
// 		unsigned long count;
// 		unsigned long count_self;
// 		unsigned int checksum;
// 		struct route_table *db;
// 	} type[BGP_LS_MAX_NLRI_TYPE];
// 	unsigned long total;
// };

/* Macros. */
// LSDB_LOOP (Tree, Node, L???)
#define LSDB_LOOP(T, N, L)                                                     \
	if ((T) != NULL)                                                       \
		for ((N) = route_top((T)); ((N)); ((N)) = route_next((N)))     \
			if (((L) = (N)->info))

// A : struct bgp_lsdb
#define NODE_LSDB(A) ((A)->lsdb->type[LINK_STATE_NODE_NLRI].db)
#define LINK_LSDB(A) ((A)->lsdb->type[LINK_STATE_LINK_NLRI].db)
#define IPV4_TOPOLOGY_PREFIX_LSDB(A)                                           \
	((A)->lsdb->type[LINK_STATE_IPV4_TOPOLOGY_PREFIX_NLRI].db)
#define IPV6_TOPOLOGY_PREFIX_LSDB(A)                                           \
	((A)->lsdb->type[LINK_STATE_IPV6_TOPOLOGY_PREFIX_NLRI].db)

struct link_state_node_nlri {
	/****MP_REACH_NLRI****/
	struct te_tlv_nlri_header *header;
	uint8_t proto_id;
	uint64_t nlri_identifier;   // identify the routing universe where the NLRI belongs.
	struct bgp_nlri_tlv_lrnd *local_node;   // can be the key
	/****LINK_STATE****/
	struct bgp_nlri_tlv_mt_id *mid;
	struct bgp_nlri_tlv_nfb *nfb;
	struct bgp_nlri_tlv_onp *onp;
	struct bgp_nlri_tlv_nn *nn;
	struct bgp_nlri_tlv_iiai *iiai;
	struct bgp_nlri_tlv_i4_rid_lrn *i4ridofln;
	struct bgp_nlri_tlv_i6_rid_lrn *i6ridofln;
	struct bgp_nlri_tlv_i4_rid_lrn *i4ridofrn;
	struct bgp_nlri_tlv_i6_rid_lrn *i6ridofrn;
};

struct link_state_link_nlri {
	/****MP_REACH_NLRI****/
	struct te_tlv_nlri_header *header;
	uint8_t proto_id;
	uint64_t nlri_identifier;
	struct bgp_nlri_tlv_lrnd *local_node;   // can be the key
	struct bgp_nlri_tlv_lrnd *remote_node;
	struct bgp_nlri_tlv_llri *llri;
	struct bgp_nlri_tlv_i4i_addr *i4ia;
	struct bgp_nlri_tlv_i4n_addr *i4na;
	struct bgp_nlri_tlv_i6i_addr *i6ia;
	struct bgp_nlri_tlv_i6n_addr *i6na;
	struct bgp_nlri_tlv_mt_id *mid;
	/****LINK_STATE****/
	struct bgp_nlri_tlv_i4_rid_lrn *i4ridofln;
	struct bgp_nlri_tlv_i6_rid_lrn *i6ridofln;
	struct bgp_nlri_tlv_i4_rid_lrn *i4ridofrn;
	struct bgp_nlri_tlv_i6_rid_lrn *i6ridofrn;
	struct bgp_nlri_tlv_agc *agc;
	struct bgp_nlri_tlv_max_link_bw *mlb;
	struct bgp_nlri_tlv_max_rsv_link_bw *mrlb;
	struct bgp_nlri_tlv_ursv_bw *urb;
	struct bgp_nlri_tlv_tdm *tdm;
	struct bgp_nlri_tlv_link_pt *lpt;
	struct bgp_nlri_tlv_mpls_pm *mpm;
	struct bgp_nlri_tlv_metric *igpm;
	struct bgp_nlri_tlv_srlg *srlg;
	struct bgp_nlri_tlv_ola *ola;
	struct bgp_nlri_tlv_lna *lna;
};

struct link_state_ipv4_nlri {
	/****MP_REACH_NLRI****/
	struct te_tlv_nlri_header *header;
	uint8_t proto_id;
	uint64_t nlri_identifier;
	struct bgp_nlri_tlv_lrnd *local_node;   // can be the key
	struct bgp_nlri_tlv_mt_id *mid;
	struct bgp_nlri_tlv_ort *ort;
	struct bgp_nlri_tlv_ip_reach *ipreach;
	/****LINK_STATE****/
	struct bgp_nlri_tlv_igp_flags *ifl;
	struct bgp_nlri_tlv_route_tag *rt;
	struct bgp_nlri_tlv_extended_tag *et;
	struct bgp_nlri_tlv_prefix_metric *pm;
	struct bgp_nlri_tlv_ospf_fowarding_adress *ofa;
	struct bgp_nlri_tlv_opa *opa;
};

struct link_state_ipv6_nlri {
	/****MP_REACH_NLRI****/
	struct te_tlv_nlri_header *header;
	uint8_t proto_id;
	uint64_t nlri_identifier;
	struct bgp_nlri_tlv_lrnd *local_node;   // can be the key
	struct bgp_nlri_tlv_mt_id *mid;
	struct bgp_nlri_tlv_ort *ort;
	struct bgp_nlri_tlv_ip_reach *ipreach;
	/****LINK_STATE****/
	struct bgp_nlri_tlv_igp_flags *ifl;
	struct bgp_nlri_tlv_route_tag *rt;
	struct bgp_nlri_tlv_extended_tag *et;
	struct bgp_nlri_tlv_prefix_metric *pm;
	struct bgp_nlri_tlv_ospf_fowarding_adress *ofa;
	struct bgp_nlri_tlv_opa *opa;
};

struct bgp_ls {
	struct te_tlv_nlri_header *header;
	struct link_state_node_nlri *node;
	struct link_state_link_nlri *link;
	struct link_state_ipv4_nlri *ipv4_prefix;
	struct link_state_ipv6_nlri *ipv6_prefix;

	/* All of reference count, also lock to remove. */
	int lock;

	/* References to this LSA in neighbor retransmission lists*/
	int retransmit_counter;

	/* Refreshement List or Queue */
	int refresh_list;
};

/* BGP LSDB related functions. */
extern void bgp_ls_unlock(struct bgp_ls **ls);
extern struct bgp_ls *bgp_ls_lock(struct bgp_ls *ls);
extern struct bgp_lsdb *bgp_lsdb_new(void);
extern void bgp_lsdb_init(struct bgp_lsdb *);
extern void bgp_lsdb_free(struct bgp_lsdb *);
extern void bgp_lsdb_cleanup(struct bgp_lsdb *);
// extern void bgp_ls_prefix_set(struct attr *lp, struct bgp_ls *ls);

/* Add bgp_ls to bgp_lsdb */
extern struct bgp_lsdb *bgp_lsdb_add(struct bgp_lsdb *, struct bgp_ls *);

/* Delete bgp_ls from bgp_lsdb */
extern void bgp_lsdb_delete(struct bgp_lsdb *, struct bgp_ls *);
// extern void bgp_lsdb_delete_all(struct bgp_lsdb *);
// extern void bgp_lsdb_delete_entry(struct bgp_lsdb *lsdb, struct route_node *rn);

extern struct bgp_ls *ls_attr_node_set(struct attr *attr);
extern struct bgp_ls *ls_attr_link_set(struct attr *attr);
extern struct bgp_ls *ls_attr_ipv4_prefix_set(struct attr *attr);
extern struct bgp_ls *ls_attr_ipv6_prefix_set(struct attr *attr);
/* Create a type of nlri_type a bgp_ls according to the attr*/
extern struct bgp_ls *ls_attr_set(struct attr *attr, uint16_t nlri_type);

extern void bgp_lsdb_clean_stat(struct bgp_lsdb *lsdb);
extern struct bgp_ls *bgp_lsdb_lookup(struct bgp_lsdb *, struct bgp_ls *);
extern struct bgp_ls *bgp_lsdb_lookup_by_id(struct bgp_lsdb *, uint8_t, struct in_addr, struct in_addr);
extern struct bgp_ls *bgp_lsdb_lookup_by_id_next(struct bgp_lsdb *, uint8_t, struct in_addr, struct in_addr, int);

extern unsigned long bgp_lsdb_count_all(struct bgp_lsdb *);
extern unsigned long bgp_lsdb_count(struct bgp_lsdb *, int);
extern unsigned long bgp_lsdb_count_self(struct bgp_lsdb *, int);
extern unsigned int bgp_lsdb_checksum(struct bgp_lsdb *, int);
extern unsigned long bgp_lsdb_isempty(struct bgp_lsdb *);
#endif /* _BGP_LS_LSDB_H */