/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"
#include "nt_util.h"

#include "hw_mod_backend.h"
#include "flm_lrn_queue.h"
#include "flow_api.h"
#include "flow_api_engine.h"
#include "flow_api_hw_db_inline.h"
#include "flow_id_table.h"
#include "stream_binary_flow_api.h"

#include "flow_api_profile_inline.h"
#include "ntnic_mod_reg.h"
#include <rte_common.h>

#define NT_FLM_MISS_FLOW_TYPE 0
#define NT_FLM_UNHANDLED_FLOW_TYPE 1
#define NT_FLM_OP_UNLEARN 0
#define NT_FLM_OP_LEARN 1

#define NT_FLM_VIOLATING_MBR_FLOW_TYPE 15
#define NT_VIOLATING_MBR_CFN 0
#define NT_VIOLATING_MBR_QSL 1

#define RTE_ETH_RSS_UDP_COMBINED                                                                  \
	(RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_NONFRAG_IPV6_UDP | RTE_ETH_RSS_IPV6_UDP_EX)

#define RTE_ETH_RSS_TCP_COMBINED                                                                  \
	(RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV6_TCP | RTE_ETH_RSS_IPV6_TCP_EX)

#define NT_FLM_OP_UNLEARN 0
#define NT_FLM_OP_LEARN 1

static void *flm_lrn_queue_arr;

static int rx_queue_idx_to_hw_id(const struct flow_eth_dev *dev, int id)
{
	for (int i = 0; i < dev->num_queues; ++i)
		if (dev->rx_queue[i].id == id)
			return dev->rx_queue[i].hw_id;

	return -1;
}

struct flm_flow_key_def_s {
	union {
		struct {
			uint64_t qw0_dyn : 7;
			uint64_t qw0_ofs : 8;
			uint64_t qw4_dyn : 7;
			uint64_t qw4_ofs : 8;
			uint64_t sw8_dyn : 7;
			uint64_t sw8_ofs : 8;
			uint64_t sw9_dyn : 7;
			uint64_t sw9_ofs : 8;
			uint64_t outer_proto : 1;
			uint64_t inner_proto : 1;
			uint64_t pad : 2;
		};
		uint64_t data;
	};
	uint32_t mask[10];
};

/*
 * Flow Matcher functionality
 */
static inline void set_key_def_qw(struct flm_flow_key_def_s *key_def, unsigned int qw,
	unsigned int dyn, unsigned int ofs)
{
	assert(qw < 2);

	if (qw == 0) {
		key_def->qw0_dyn = dyn & 0x7f;
		key_def->qw0_ofs = ofs & 0xff;

	} else {
		key_def->qw4_dyn = dyn & 0x7f;
		key_def->qw4_ofs = ofs & 0xff;
	}
}

static inline void set_key_def_sw(struct flm_flow_key_def_s *key_def, unsigned int sw,
	unsigned int dyn, unsigned int ofs)
{
	assert(sw < 2);

	if (sw == 0) {
		key_def->sw8_dyn = dyn & 0x7f;
		key_def->sw8_ofs = ofs & 0xff;

	} else {
		key_def->sw9_dyn = dyn & 0x7f;
		key_def->sw9_ofs = ofs & 0xff;
	}
}

static uint8_t get_port_from_port_id(const struct flow_nic_dev *ndev, uint32_t port_id)
{
	struct flow_eth_dev *dev = ndev->eth_base;

	while (dev) {
		if (dev->port_id == port_id)
			return dev->port;

		dev = dev->next;
	}

	return UINT8_MAX;
}

static void nic_insert_flow(struct flow_nic_dev *ndev, struct flow_handle *fh)
{
	pthread_mutex_lock(&ndev->flow_mtx);

	if (ndev->flow_base)
		ndev->flow_base->prev = fh;

	fh->next = ndev->flow_base;
	fh->prev = NULL;
	ndev->flow_base = fh;

	pthread_mutex_unlock(&ndev->flow_mtx);
}

static void nic_remove_flow(struct flow_nic_dev *ndev, struct flow_handle *fh)
{
	struct flow_handle *next = fh->next;
	struct flow_handle *prev = fh->prev;

	pthread_mutex_lock(&ndev->flow_mtx);

	if (next && prev) {
		prev->next = next;
		next->prev = prev;

	} else if (next) {
		ndev->flow_base = next;
		next->prev = NULL;

	} else if (prev) {
		prev->next = NULL;

	} else if (ndev->flow_base == fh) {
		ndev->flow_base = NULL;
	}

	pthread_mutex_unlock(&ndev->flow_mtx);
}

static void nic_insert_flow_flm(struct flow_nic_dev *ndev, struct flow_handle *fh)
{
	pthread_mutex_lock(&ndev->flow_mtx);

	if (ndev->flow_base_flm)
		ndev->flow_base_flm->prev = fh;

	fh->next = ndev->flow_base_flm;
	fh->prev = NULL;
	ndev->flow_base_flm = fh;

	pthread_mutex_unlock(&ndev->flow_mtx);
}

static void nic_remove_flow_flm(struct flow_nic_dev *ndev, struct flow_handle *fh_flm)
{
	struct flow_handle *next = fh_flm->next;
	struct flow_handle *prev = fh_flm->prev;

	pthread_mutex_lock(&ndev->flow_mtx);

	if (next && prev) {
		prev->next = next;
		next->prev = prev;

	} else if (next) {
		ndev->flow_base_flm = next;
		next->prev = NULL;

	} else if (prev) {
		prev->next = NULL;

	} else if (ndev->flow_base_flm == fh_flm) {
		ndev->flow_base_flm = NULL;
	}

	pthread_mutex_unlock(&ndev->flow_mtx);
}

static inline struct nic_flow_def *prepare_nic_flow_def(struct nic_flow_def *fd)
{
	if (fd) {
		fd->full_offload = -1;
		fd->in_port_override = -1;
		fd->mark = UINT32_MAX;
		fd->jump_to_group = UINT32_MAX;

		fd->l2_prot = -1;
		fd->l3_prot = -1;
		fd->l4_prot = -1;
		fd->vlans = 0;
		fd->tunnel_prot = -1;
		fd->tunnel_l3_prot = -1;
		fd->tunnel_l4_prot = -1;
		fd->fragmentation = -1;
		fd->ip_prot = -1;
		fd->tunnel_ip_prot = -1;

		fd->non_empty = -1;
	}

	return fd;
}

static inline struct nic_flow_def *allocate_nic_flow_def(void)
{
	return prepare_nic_flow_def(calloc(1, sizeof(struct nic_flow_def)));
}

static bool fd_has_empty_pattern(const struct nic_flow_def *fd)
{
	return fd && fd->vlans == 0 && fd->l2_prot < 0 && fd->l3_prot < 0 && fd->l4_prot < 0 &&
		fd->tunnel_prot < 0 && fd->tunnel_l3_prot < 0 && fd->tunnel_l4_prot < 0 &&
		fd->ip_prot < 0 && fd->tunnel_ip_prot < 0 && fd->non_empty < 0;
}

static inline const void *memcpy_mask_if(void *dest, const void *src, const void *mask,
	size_t count)
{
	if (mask == NULL)
		return src;

	unsigned char *dest_ptr = (unsigned char *)dest;
	const unsigned char *src_ptr = (const unsigned char *)src;
	const unsigned char *mask_ptr = (const unsigned char *)mask;

	for (size_t i = 0; i < count; ++i)
		dest_ptr[i] = src_ptr[i] & mask_ptr[i];

	return dest;
}

static int flm_flow_programming(struct flow_handle *fh, uint32_t flm_op)
{
	struct flm_v25_lrn_data_s *learn_record = NULL;

	if (fh->type != FLOW_HANDLE_TYPE_FLM)
		return -1;

	if (flm_op == NT_FLM_OP_LEARN) {
		union flm_handles flm_h;
		flm_h.p = fh;
		fh->flm_id = ntnic_id_table_get_id(fh->dev->ndev->id_table_handle, flm_h,
			fh->caller_id, 1);
	}

	uint32_t flm_id = fh->flm_id;

	if (flm_op == NT_FLM_OP_UNLEARN) {
		ntnic_id_table_free_id(fh->dev->ndev->id_table_handle, flm_id);

		if (fh->learn_ignored == 1)
			return 0;
	}

	learn_record =
		(struct flm_v25_lrn_data_s *)
			flm_lrn_queue_get_write_buffer(flm_lrn_queue_arr);

	while (learn_record == NULL) {
		nt_os_wait_usec(1);
		learn_record =
			(struct flm_v25_lrn_data_s *)
			flm_lrn_queue_get_write_buffer(flm_lrn_queue_arr);
	}

	memset(learn_record, 0x0, sizeof(struct flm_v25_lrn_data_s));

	learn_record->id = flm_id;

	learn_record->qw0[0] = fh->flm_data[9];
	learn_record->qw0[1] = fh->flm_data[8];
	learn_record->qw0[2] = fh->flm_data[7];
	learn_record->qw0[3] = fh->flm_data[6];
	learn_record->qw4[0] = fh->flm_data[5];
	learn_record->qw4[1] = fh->flm_data[4];
	learn_record->qw4[2] = fh->flm_data[3];
	learn_record->qw4[3] = fh->flm_data[2];
	learn_record->sw8 = fh->flm_data[1];
	learn_record->sw9 = fh->flm_data[0];
	learn_record->prot = fh->flm_prot;

	/* Last non-zero mtr is used for statistics */
	uint8_t mbrs = 0;

	learn_record->vol_idx = mbrs;

	learn_record->nat_ip = fh->flm_nat_ipv4;
	learn_record->nat_port = fh->flm_nat_port;
	learn_record->nat_en = fh->flm_nat_ipv4 || fh->flm_nat_port ? 1 : 0;

	learn_record->dscp = fh->flm_dscp;
	learn_record->teid = fh->flm_teid;
	learn_record->qfi = fh->flm_qfi;
	learn_record->rqi = fh->flm_rqi;
	/* Lower 10 bits used for RPL EXT PTR */
	learn_record->color = fh->flm_rpl_ext_ptr & 0x3ff;

	learn_record->ent = 0;
	learn_record->op = flm_op & 0xf;
	/* Suppress generation of statistics INF_DATA */
	learn_record->nofi = 1;
	learn_record->prio = fh->flm_prio & 0x3;
	learn_record->ft = fh->flm_ft;
	learn_record->kid = fh->flm_kid;
	learn_record->eor = 1;
	learn_record->scrub_prof = 0;

	flm_lrn_queue_release_write_buffer(flm_lrn_queue_arr);
	return 0;
}

/*
 * This function must be callable without locking any mutexes
 */
static int interpret_flow_actions(const struct flow_eth_dev *dev,
	const struct rte_flow_action action[],
	const struct rte_flow_action *action_mask,
	struct nic_flow_def *fd,
	struct rte_flow_error *error,
	uint32_t *num_dest_port,
	uint32_t *num_queues)
{
	unsigned int encap_decap_order = 0;

	uint64_t modify_field_use_flags = 0x0;

	*num_dest_port = 0;
	*num_queues = 0;

	if (action == NULL) {
		flow_nic_set_error(ERR_FAILED, error);
		NT_LOG(ERR, FILTER, "Flow actions missing");
		return -1;
	}

	/*
	 * Gather flow match + actions and convert into internal flow definition structure (struct
	 * nic_flow_def_s) This is the 1st step in the flow creation - validate, convert and
	 * prepare
	 */
	for (int aidx = 0; action[aidx].type != RTE_FLOW_ACTION_TYPE_END; ++aidx) {
		switch (action[aidx].type) {
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			NT_LOG(DBG, FILTER, "Dev:%p: RTE_FLOW_ACTION_TYPE_PORT_ID", dev);

			if (action[aidx].conf) {
				struct rte_flow_action_port_id port_id_tmp;
				const struct rte_flow_action_port_id *port_id =
					memcpy_mask_if(&port_id_tmp, action[aidx].conf,
					action_mask ? action_mask[aidx].conf : NULL,
					sizeof(struct rte_flow_action_port_id));

				if (*num_dest_port > 0) {
					NT_LOG(ERR, FILTER,
						"Multiple port_id actions for one flow is not supported");
					flow_nic_set_error(ERR_ACTION_MULTIPLE_PORT_ID_UNSUPPORTED,
						error);
					return -1;
				}

				uint8_t port = get_port_from_port_id(dev->ndev, port_id->id);

				if (fd->dst_num_avail == MAX_OUTPUT_DEST) {
					NT_LOG(ERR, FILTER, "Too many output destinations");
					flow_nic_set_error(ERR_OUTPUT_TOO_MANY, error);
					return -1;
				}

				if (port >= dev->ndev->be.num_phy_ports) {
					NT_LOG(ERR, FILTER, "Phy port out of range");
					flow_nic_set_error(ERR_OUTPUT_INVALID, error);
					return -1;
				}

				/* New destination port to add */
				fd->dst_id[fd->dst_num_avail].owning_port_id = port_id->id;
				fd->dst_id[fd->dst_num_avail].type = PORT_PHY;
				fd->dst_id[fd->dst_num_avail].id = (int)port;
				fd->dst_id[fd->dst_num_avail].active = 1;
				fd->dst_num_avail++;

				if (fd->full_offload < 0)
					fd->full_offload = 1;

				*num_dest_port += 1;

				NT_LOG(DBG, FILTER, "Phy port ID: %i", (int)port);
			}

			break;

		case RTE_FLOW_ACTION_TYPE_QUEUE:
			NT_LOG(DBG, FILTER, "Dev:%p: RTE_FLOW_ACTION_TYPE_QUEUE", dev);

			if (action[aidx].conf) {
				struct rte_flow_action_queue queue_tmp;
				const struct rte_flow_action_queue *queue =
					memcpy_mask_if(&queue_tmp, action[aidx].conf,
					action_mask ? action_mask[aidx].conf : NULL,
					sizeof(struct rte_flow_action_queue));

				int hw_id = rx_queue_idx_to_hw_id(dev, queue->index);

				fd->dst_id[fd->dst_num_avail].owning_port_id = dev->port;
				fd->dst_id[fd->dst_num_avail].id = hw_id;
				fd->dst_id[fd->dst_num_avail].type = PORT_VIRT;
				fd->dst_id[fd->dst_num_avail].active = 1;
				fd->dst_num_avail++;

				NT_LOG(DBG, FILTER,
					"Dev:%p: RTE_FLOW_ACTION_TYPE_QUEUE port %u, queue index: %u, hw id %u",
					dev, dev->port, queue->index, hw_id);

				fd->full_offload = 0;
				*num_queues += 1;
			}

			break;

		case RTE_FLOW_ACTION_TYPE_MARK:
			NT_LOG(DBG, FILTER, "Dev:%p: RTE_FLOW_ACTION_TYPE_MARK", dev);

			if (action[aidx].conf) {
				struct rte_flow_action_mark mark_tmp;
				const struct rte_flow_action_mark *mark =
					memcpy_mask_if(&mark_tmp, action[aidx].conf,
					action_mask ? action_mask[aidx].conf : NULL,
					sizeof(struct rte_flow_action_mark));

				fd->mark = mark->id;
				NT_LOG(DBG, FILTER, "Mark: %i", mark->id);
			}

			break;

		case RTE_FLOW_ACTION_TYPE_JUMP:
			NT_LOG(DBG, FILTER, "Dev:%p: RTE_FLOW_ACTION_TYPE_JUMP", dev);

			if (action[aidx].conf) {
				struct rte_flow_action_jump jump_tmp;
				const struct rte_flow_action_jump *jump =
					memcpy_mask_if(&jump_tmp, action[aidx].conf,
					action_mask ? action_mask[aidx].conf : NULL,
					sizeof(struct rte_flow_action_jump));

				fd->jump_to_group = jump->group;
				NT_LOG(DBG, FILTER, "Dev:%p: RTE_FLOW_ACTION_TYPE_JUMP: group %u",
					dev, jump->group);
			}

			break;

		case RTE_FLOW_ACTION_TYPE_DROP:
			NT_LOG(DBG, FILTER, "Dev:%p: RTE_FLOW_ACTION_TYPE_DROP", dev);

			if (action[aidx].conf) {
				fd->dst_id[fd->dst_num_avail].owning_port_id = 0;
				fd->dst_id[fd->dst_num_avail].id = 0;
				fd->dst_id[fd->dst_num_avail].type = PORT_NONE;
				fd->dst_num_avail++;
			}

			break;

		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			NT_LOG(DBG, FILTER, "Dev:%p: RTE_FLOW_ACTION_TYPE_RAW_ENCAP", dev);

			if (action[aidx].conf) {
				const struct flow_action_raw_encap *encap =
					(const struct flow_action_raw_encap *)action[aidx].conf;
				const struct flow_action_raw_encap *encap_mask = action_mask
					? (const struct flow_action_raw_encap *)action_mask[aidx]
					.conf
					: NULL;
				const struct rte_flow_item *items = encap->items;

				if (encap_decap_order != 1) {
					NT_LOG(ERR, FILTER,
						"ERROR: - RAW_ENCAP must follow RAW_DECAP.");
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
					return -1;
				}

				if (encap->size == 0 || encap->size > 255 ||
					encap->item_count < 2) {
					NT_LOG(ERR, FILTER,
						"ERROR: - RAW_ENCAP data/size invalid.");
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
					return -1;
				}

				encap_decap_order = 2;

				fd->tun_hdr.len = (uint8_t)encap->size;

				if (encap_mask) {
					memcpy_mask_if(fd->tun_hdr.d.hdr8, encap->data,
						encap_mask->data, fd->tun_hdr.len);

				} else {
					memcpy(fd->tun_hdr.d.hdr8, encap->data, fd->tun_hdr.len);
				}

				while (items->type != RTE_FLOW_ITEM_TYPE_END) {
					switch (items->type) {
					case RTE_FLOW_ITEM_TYPE_ETH:
						fd->tun_hdr.l2_len = 14;
						break;

					case RTE_FLOW_ITEM_TYPE_VLAN:
						fd->tun_hdr.nb_vlans += 1;
						fd->tun_hdr.l2_len += 4;
						break;

					case RTE_FLOW_ITEM_TYPE_IPV4:
						fd->tun_hdr.ip_version = 4;
						fd->tun_hdr.l3_len = sizeof(struct rte_ipv4_hdr);
						fd->tun_hdr.new_outer = 1;

						/* Patch length */
						fd->tun_hdr.d.hdr8[fd->tun_hdr.l2_len + 2] = 0x07;
						fd->tun_hdr.d.hdr8[fd->tun_hdr.l2_len + 3] = 0xfd;
						break;

					case RTE_FLOW_ITEM_TYPE_IPV6:
						fd->tun_hdr.ip_version = 6;
						fd->tun_hdr.l3_len = sizeof(struct rte_ipv6_hdr);
						fd->tun_hdr.new_outer = 1;

						/* Patch length */
						fd->tun_hdr.d.hdr8[fd->tun_hdr.l2_len + 4] = 0x07;
						fd->tun_hdr.d.hdr8[fd->tun_hdr.l2_len + 5] = 0xfd;
						break;

					case RTE_FLOW_ITEM_TYPE_SCTP:
						fd->tun_hdr.l4_len = sizeof(struct rte_sctp_hdr);
						break;

					case RTE_FLOW_ITEM_TYPE_TCP:
						fd->tun_hdr.l4_len = sizeof(struct rte_tcp_hdr);
						break;

					case RTE_FLOW_ITEM_TYPE_UDP:
						fd->tun_hdr.l4_len = sizeof(struct rte_udp_hdr);

						/* Patch length */
						fd->tun_hdr.d.hdr8[fd->tun_hdr.l2_len +
							fd->tun_hdr.l3_len + 4] = 0x07;
						fd->tun_hdr.d.hdr8[fd->tun_hdr.l2_len +
							fd->tun_hdr.l3_len + 5] = 0xfd;
						break;

					case RTE_FLOW_ITEM_TYPE_ICMP:
						fd->tun_hdr.l4_len = sizeof(struct rte_icmp_hdr);
						break;

					case RTE_FLOW_ITEM_TYPE_ICMP6:
						fd->tun_hdr.l4_len =
							sizeof(struct rte_flow_item_icmp6);
						break;

					case RTE_FLOW_ITEM_TYPE_GTP:
						/* Patch length */
						fd->tun_hdr.d.hdr8[fd->tun_hdr.l2_len +
							fd->tun_hdr.l3_len +
							fd->tun_hdr.l4_len + 2] = 0x07;
						fd->tun_hdr.d.hdr8[fd->tun_hdr.l2_len +
							fd->tun_hdr.l3_len +
							fd->tun_hdr.l4_len + 3] = 0xfd;
						break;

					default:
						break;
					}

					items++;
				}

				if (fd->tun_hdr.nb_vlans > 3) {
					NT_LOG(ERR, FILTER,
						"ERROR: - Encapsulation with %d vlans not supported.",
						(int)fd->tun_hdr.nb_vlans);
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
					return -1;
				}

				/* Convert encap data to 128-bit little endian */
				for (size_t i = 0; i < (encap->size + 15) / 16; ++i) {
					uint8_t *data = fd->tun_hdr.d.hdr8 + i * 16;

					for (unsigned int j = 0; j < 8; ++j) {
						uint8_t t = data[j];
						data[j] = data[15 - j];
						data[15 - j] = t;
					}
				}
			}

			break;

		case RTE_FLOW_ACTION_TYPE_RAW_DECAP:
			NT_LOG(DBG, FILTER, "Dev:%p: RTE_FLOW_ACTION_TYPE_RAW_DECAP", dev);

			if (action[aidx].conf) {
				/* Mask is N/A for RAW_DECAP */
				const struct flow_action_raw_decap *decap =
					(const struct flow_action_raw_decap *)action[aidx].conf;

				if (encap_decap_order != 0) {
					NT_LOG(ERR, FILTER,
						"ERROR: - RAW_ENCAP must follow RAW_DECAP.");
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
					return -1;
				}

				if (decap->item_count < 2) {
					NT_LOG(ERR, FILTER,
						"ERROR: - RAW_DECAP must decap something.");
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
					return -1;
				}

				encap_decap_order = 1;

				switch (decap->items[decap->item_count - 2].type) {
				case RTE_FLOW_ITEM_TYPE_ETH:
				case RTE_FLOW_ITEM_TYPE_VLAN:
					fd->header_strip_end_dyn = DYN_L3;
					fd->header_strip_end_ofs = 0;
					break;

				case RTE_FLOW_ITEM_TYPE_IPV4:
				case RTE_FLOW_ITEM_TYPE_IPV6:
					fd->header_strip_end_dyn = DYN_L4;
					fd->header_strip_end_ofs = 0;
					break;

				case RTE_FLOW_ITEM_TYPE_SCTP:
				case RTE_FLOW_ITEM_TYPE_TCP:
				case RTE_FLOW_ITEM_TYPE_UDP:
				case RTE_FLOW_ITEM_TYPE_ICMP:
				case RTE_FLOW_ITEM_TYPE_ICMP6:
					fd->header_strip_end_dyn = DYN_L4_PAYLOAD;
					fd->header_strip_end_ofs = 0;
					break;

				case RTE_FLOW_ITEM_TYPE_GTP:
					fd->header_strip_end_dyn = DYN_TUN_L3;
					fd->header_strip_end_ofs = 0;
					break;

				default:
					fd->header_strip_end_dyn = DYN_L2;
					fd->header_strip_end_ofs = 0;
					break;
				}
			}

			break;

		case RTE_FLOW_ACTION_TYPE_MODIFY_FIELD:
			NT_LOG(DBG, FILTER, "Dev:%p: RTE_FLOW_ACTION_TYPE_MODIFY_FIELD", dev);
			{
				/* Note: This copy method will not work for FLOW_FIELD_POINTER */
				struct rte_flow_action_modify_field modify_field_tmp;
				const struct rte_flow_action_modify_field *modify_field =
					memcpy_mask_if(&modify_field_tmp, action[aidx].conf,
					action_mask ? action_mask[aidx].conf : NULL,
					sizeof(struct rte_flow_action_modify_field));

				uint64_t modify_field_use_flag = 0;

				if (modify_field->src.field != RTE_FLOW_FIELD_VALUE) {
					NT_LOG(ERR, FILTER,
						"MODIFY_FIELD only src type VALUE is supported.");
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
					return -1;
				}

				if (modify_field->dst.level > 2) {
					NT_LOG(ERR, FILTER,
						"MODIFY_FIELD only dst level 0, 1, and 2 is supported.");
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
					return -1;
				}

				if (modify_field->dst.field == RTE_FLOW_FIELD_IPV4_TTL ||
					modify_field->dst.field == RTE_FLOW_FIELD_IPV6_HOPLIMIT) {
					if (modify_field->operation != RTE_FLOW_MODIFY_SUB) {
						NT_LOG(ERR, FILTER,
							"MODIFY_FIELD only operation SUB is supported for TTL/HOPLIMIT.");
						flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
						return -1;
					}

					if (fd->ttl_sub_enable) {
						NT_LOG(ERR, FILTER,
							"MODIFY_FIELD TTL/HOPLIMIT resource already in use.");
						flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
						return -1;
					}

					fd->ttl_sub_enable = 1;
					fd->ttl_sub_ipv4 =
						(modify_field->dst.field == RTE_FLOW_FIELD_IPV4_TTL)
						? 1
						: 0;
					fd->ttl_sub_outer = (modify_field->dst.level <= 1) ? 1 : 0;

				} else {
					if (modify_field->operation != RTE_FLOW_MODIFY_SET) {
						NT_LOG(ERR, FILTER,
							"MODIFY_FIELD only operation SET is supported in general.");
						flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
						return -1;
					}

					if (fd->modify_field_count >=
						dev->ndev->be.tpe.nb_cpy_writers) {
						NT_LOG(ERR, FILTER,
							"MODIFY_FIELD exceeded maximum of %u MODIFY_FIELD actions.",
							dev->ndev->be.tpe.nb_cpy_writers);
						flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
						return -1;
					}

					int mod_outer = modify_field->dst.level <= 1;

					switch (modify_field->dst.field) {
					case RTE_FLOW_FIELD_IPV4_DSCP:
						fd->modify_field[fd->modify_field_count].select =
							CPY_SELECT_DSCP_IPV4;
						fd->modify_field[fd->modify_field_count].dyn =
							mod_outer ? DYN_L3 : DYN_TUN_L3;
						fd->modify_field[fd->modify_field_count].ofs = 1;
						fd->modify_field[fd->modify_field_count].len = 1;
						break;

					case RTE_FLOW_FIELD_IPV6_DSCP:
						fd->modify_field[fd->modify_field_count].select =
							CPY_SELECT_DSCP_IPV6;
						fd->modify_field[fd->modify_field_count].dyn =
							mod_outer ? DYN_L3 : DYN_TUN_L3;
						fd->modify_field[fd->modify_field_count].ofs = 0;
						/*
						 * len=2 is needed because
						 * IPv6 DSCP overlaps 2 bytes.
						 */
						fd->modify_field[fd->modify_field_count].len = 2;
						break;

					case RTE_FLOW_FIELD_GTP_PSC_QFI:
						fd->modify_field[fd->modify_field_count].select =
							CPY_SELECT_RQI_QFI;
						fd->modify_field[fd->modify_field_count].dyn =
							mod_outer ? DYN_L4_PAYLOAD
							: DYN_TUN_L4_PAYLOAD;
						fd->modify_field[fd->modify_field_count].ofs = 14;
						fd->modify_field[fd->modify_field_count].len = 1;
						break;

					case RTE_FLOW_FIELD_IPV4_SRC:
						fd->modify_field[fd->modify_field_count].select =
							CPY_SELECT_IPV4;
						fd->modify_field[fd->modify_field_count].dyn =
							mod_outer ? DYN_L3 : DYN_TUN_L3;
						fd->modify_field[fd->modify_field_count].ofs = 12;
						fd->modify_field[fd->modify_field_count].len = 4;
						break;

					case RTE_FLOW_FIELD_IPV4_DST:
						fd->modify_field[fd->modify_field_count].select =
							CPY_SELECT_IPV4;
						fd->modify_field[fd->modify_field_count].dyn =
							mod_outer ? DYN_L3 : DYN_TUN_L3;
						fd->modify_field[fd->modify_field_count].ofs = 16;
						fd->modify_field[fd->modify_field_count].len = 4;
						break;

					case RTE_FLOW_FIELD_TCP_PORT_SRC:
					case RTE_FLOW_FIELD_UDP_PORT_SRC:
						fd->modify_field[fd->modify_field_count].select =
							CPY_SELECT_PORT;
						fd->modify_field[fd->modify_field_count].dyn =
							mod_outer ? DYN_L4 : DYN_TUN_L4;
						fd->modify_field[fd->modify_field_count].ofs = 0;
						fd->modify_field[fd->modify_field_count].len = 2;
						break;

					case RTE_FLOW_FIELD_TCP_PORT_DST:
					case RTE_FLOW_FIELD_UDP_PORT_DST:
						fd->modify_field[fd->modify_field_count].select =
							CPY_SELECT_PORT;
						fd->modify_field[fd->modify_field_count].dyn =
							mod_outer ? DYN_L4 : DYN_TUN_L4;
						fd->modify_field[fd->modify_field_count].ofs = 2;
						fd->modify_field[fd->modify_field_count].len = 2;
						break;

					case RTE_FLOW_FIELD_GTP_TEID:
						fd->modify_field[fd->modify_field_count].select =
							CPY_SELECT_TEID;
						fd->modify_field[fd->modify_field_count].dyn =
							mod_outer ? DYN_L4_PAYLOAD
							: DYN_TUN_L4_PAYLOAD;
						fd->modify_field[fd->modify_field_count].ofs = 4;
						fd->modify_field[fd->modify_field_count].len = 4;
						break;

					default:
						NT_LOG(ERR, FILTER,
							"MODIFY_FIELD dst type is not supported.");
						flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
						return -1;
					}

					modify_field_use_flag = 1
						<< fd->modify_field[fd->modify_field_count].select;

					if (modify_field_use_flag & modify_field_use_flags) {
						NT_LOG(ERR, FILTER,
							"MODIFY_FIELD dst type hardware resource already used.");
						flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
						return -1;
					}

					memcpy(fd->modify_field[fd->modify_field_count].value8,
						modify_field->src.value, 16);

					fd->modify_field[fd->modify_field_count].level =
						modify_field->dst.level;

					modify_field_use_flags |= modify_field_use_flag;
					fd->modify_field_count += 1;
				}
			}

			break;

		default:
			NT_LOG(ERR, FILTER, "Invalid or unsupported flow action received - %i",
				action[aidx].type);
			flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
			return -1;
		}
	}

	if (!(encap_decap_order == 0 || encap_decap_order == 2)) {
		NT_LOG(ERR, FILTER, "Invalid encap/decap actions");
		return -1;
	}

	return 0;
}

static int interpret_flow_elements(const struct flow_eth_dev *dev,
	const struct rte_flow_item elem[],
	struct nic_flow_def *fd __rte_unused,
	struct rte_flow_error *error,
	uint16_t implicit_vlan_vid __rte_unused,
	uint32_t *in_port_id,
	uint32_t *packet_data,
	uint32_t *packet_mask,
	struct flm_flow_key_def_s *key_def)
{
	uint32_t any_count = 0;

	unsigned int qw_counter = 0;
	unsigned int sw_counter = 0;

	*in_port_id = UINT32_MAX;

	memset(packet_data, 0x0, sizeof(uint32_t) * 10);
	memset(packet_mask, 0x0, sizeof(uint32_t) * 10);
	memset(key_def, 0x0, sizeof(struct flm_flow_key_def_s));

	if (elem == NULL) {
		flow_nic_set_error(ERR_FAILED, error);
		NT_LOG(ERR, FILTER, "Flow items missing");
		return -1;
	}

	if (implicit_vlan_vid > 0) {
		uint32_t *sw_data = &packet_data[1 - sw_counter];
		uint32_t *sw_mask = &packet_mask[1 - sw_counter];

		sw_mask[0] = 0x0fff;
		sw_data[0] = implicit_vlan_vid & sw_mask[0];

		km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1, DYN_FIRST_VLAN, 0);
		set_key_def_sw(key_def, sw_counter, DYN_FIRST_VLAN, 0);
		sw_counter += 1;

		fd->vlans += 1;
	}

	int qw_reserved_mac = 0;
	int qw_reserved_ipv6 = 0;

	for (int eidx = 0; elem[eidx].type != RTE_FLOW_ITEM_TYPE_END; ++eidx) {
		switch (elem[eidx].type) {
		case RTE_FLOW_ITEM_TYPE_ETH: {
			const struct rte_ether_hdr *eth_spec =
				(const struct rte_ether_hdr *)elem[eidx].spec;
			const struct rte_ether_hdr *eth_mask =
				(const struct rte_ether_hdr *)elem[eidx].mask;

			if (eth_spec != NULL && eth_mask != NULL) {
				if (is_non_zero(eth_mask->dst_addr.addr_bytes, 6) ||
					is_non_zero(eth_mask->src_addr.addr_bytes, 6)) {
					qw_reserved_mac += 1;
				}
			}
		}
		break;

		case RTE_FLOW_ITEM_TYPE_IPV6: {
			const struct rte_flow_item_ipv6 *ipv6_spec =
				(const struct rte_flow_item_ipv6 *)elem[eidx].spec;
			const struct rte_flow_item_ipv6 *ipv6_mask =
				(const struct rte_flow_item_ipv6 *)elem[eidx].mask;

			if (ipv6_spec != NULL && ipv6_mask != NULL) {
				if (is_non_zero(&ipv6_spec->hdr.src_addr, 16))
					qw_reserved_ipv6 += 1;

				if (is_non_zero(&ipv6_spec->hdr.dst_addr, 16))
					qw_reserved_ipv6 += 1;
			}
		}
		break;

		default:
			break;
		}
	}

	int qw_free = 2 - qw_reserved_mac - qw_reserved_ipv6;

	if (qw_free < 0) {
		NT_LOG(ERR, FILTER, "Key size too big. Out of QW resources.");
		flow_nic_set_error(ERR_FAILED, error);
		return -1;
	}

	for (int eidx = 0; elem[eidx].type != RTE_FLOW_ITEM_TYPE_END; ++eidx) {
		switch (elem[eidx].type) {
		case RTE_FLOW_ITEM_TYPE_ANY:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_ANY",
				dev->ndev->adapter_no, dev->port);
			any_count += 1;
			break;

		case RTE_FLOW_ITEM_TYPE_ETH:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_ETH",
				dev->ndev->adapter_no, dev->port);
			{
				const struct rte_ether_hdr *eth_spec =
					(const struct rte_ether_hdr *)elem[eidx].spec;
				const struct rte_ether_hdr *eth_mask =
					(const struct rte_ether_hdr *)elem[eidx].mask;

				if (any_count > 0) {
					NT_LOG(ERR, FILTER,
						"Tunneled L2 ethernet not supported");
					flow_nic_set_error(ERR_FAILED, error);
					return -1;
				}

				if (eth_spec == NULL || eth_mask == NULL) {
					fd->l2_prot = PROT_L2_ETH2;
					break;
				}

				int non_zero = is_non_zero(eth_mask->dst_addr.addr_bytes, 6) ||
					is_non_zero(eth_mask->src_addr.addr_bytes, 6);

				if (non_zero ||
					(eth_mask->ether_type != 0 && sw_counter >= 2)) {
					if (qw_counter >= 2) {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of QW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}

					uint32_t *qw_data =
						&packet_data[2 + 4 - qw_counter * 4];
					uint32_t *qw_mask =
						&packet_mask[2 + 4 - qw_counter * 4];

					qw_data[0] = ((eth_spec->dst_addr.addr_bytes[0] &
						eth_mask->dst_addr.addr_bytes[0]) << 24) +
						((eth_spec->dst_addr.addr_bytes[1] &
						eth_mask->dst_addr.addr_bytes[1]) << 16) +
						((eth_spec->dst_addr.addr_bytes[2] &
						eth_mask->dst_addr.addr_bytes[2]) << 8) +
						(eth_spec->dst_addr.addr_bytes[3] &
						eth_mask->dst_addr.addr_bytes[3]);

					qw_data[1] = ((eth_spec->dst_addr.addr_bytes[4] &
						eth_mask->dst_addr.addr_bytes[4]) << 24) +
						((eth_spec->dst_addr.addr_bytes[5] &
						eth_mask->dst_addr.addr_bytes[5]) << 16) +
						((eth_spec->src_addr.addr_bytes[0] &
						eth_mask->src_addr.addr_bytes[0]) << 8) +
						(eth_spec->src_addr.addr_bytes[1] &
						eth_mask->src_addr.addr_bytes[1]);

					qw_data[2] = ((eth_spec->src_addr.addr_bytes[2] &
						eth_mask->src_addr.addr_bytes[2]) << 24) +
						((eth_spec->src_addr.addr_bytes[3] &
						eth_mask->src_addr.addr_bytes[3]) << 16) +
						((eth_spec->src_addr.addr_bytes[4] &
						eth_mask->src_addr.addr_bytes[4]) << 8) +
						(eth_spec->src_addr.addr_bytes[5] &
						eth_mask->src_addr.addr_bytes[5]);

					qw_data[3] = ntohs(eth_spec->ether_type &
						eth_mask->ether_type) << 16;

					qw_mask[0] = (eth_mask->dst_addr.addr_bytes[0] << 24) +
						(eth_mask->dst_addr.addr_bytes[1] << 16) +
						(eth_mask->dst_addr.addr_bytes[2] << 8) +
						eth_mask->dst_addr.addr_bytes[3];

					qw_mask[1] = (eth_mask->dst_addr.addr_bytes[4] << 24) +
						(eth_mask->dst_addr.addr_bytes[5] << 16) +
						(eth_mask->src_addr.addr_bytes[0] << 8) +
						eth_mask->src_addr.addr_bytes[1];

					qw_mask[2] = (eth_mask->src_addr.addr_bytes[2] << 24) +
						(eth_mask->src_addr.addr_bytes[3] << 16) +
						(eth_mask->src_addr.addr_bytes[4] << 8) +
						eth_mask->src_addr.addr_bytes[5];

					qw_mask[3] = ntohs(eth_mask->ether_type) << 16;

					km_add_match_elem(&fd->km,
						&qw_data[(size_t)(qw_counter * 4)],
						&qw_mask[(size_t)(qw_counter * 4)], 4, DYN_L2, 0);
					set_key_def_qw(key_def, qw_counter, DYN_L2, 0);
					qw_counter += 1;

					if (!non_zero)
						qw_free -= 1;

				} else if (eth_mask->ether_type != 0) {
					if (sw_counter >= 2) {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of SW-QW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}

					uint32_t *sw_data = &packet_data[1 - sw_counter];
					uint32_t *sw_mask = &packet_mask[1 - sw_counter];

					sw_mask[0] = ntohs(eth_mask->ether_type) << 16;
					sw_data[0] = ntohs(eth_spec->ether_type) << 16 & sw_mask[0];

					km_add_match_elem(&fd->km, &sw_data[0],
						&sw_mask[0], 1, DYN_L2, 12);
					set_key_def_sw(key_def, sw_counter, DYN_L2, 12);
					sw_counter += 1;
				}

				fd->l2_prot = PROT_L2_ETH2;
			}

			break;

		case RTE_FLOW_ITEM_TYPE_VLAN:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_VLAN",
				dev->ndev->adapter_no, dev->port);
			{
				const struct rte_vlan_hdr *vlan_spec =
					(const struct rte_vlan_hdr *)elem[eidx].spec;
				const struct rte_vlan_hdr *vlan_mask =
					(const struct rte_vlan_hdr *)elem[eidx].mask;

				if (vlan_spec == NULL || vlan_mask == NULL) {
					fd->vlans += 1;
					break;
				}

				if (!vlan_mask->vlan_tci && !vlan_mask->eth_proto)
					break;

				if (implicit_vlan_vid > 0) {
					NT_LOG(ERR, FILTER,
						"Multiple VLANs not supported for implicit VLAN patterns.");
					flow_nic_set_error(ERR_MATCH_INVALID_OR_UNSUPPORTED_ELEM,
						error);
					return -1;
				}

				if (sw_counter < 2) {
					uint32_t *sw_data = &packet_data[1 - sw_counter];
					uint32_t *sw_mask = &packet_mask[1 - sw_counter];

					sw_mask[0] = ntohs(vlan_mask->vlan_tci) << 16 |
						ntohs(vlan_mask->eth_proto);
					sw_data[0] = ntohs(vlan_spec->vlan_tci) << 16 |
						ntohs(vlan_spec->eth_proto);
					sw_data[0] &= sw_mask[0];

					km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1,
						DYN_FIRST_VLAN, 2 + 4 * fd->vlans);
					set_key_def_sw(key_def, sw_counter, DYN_FIRST_VLAN,
						2 + 4 * fd->vlans);
					sw_counter += 1;

				} else if (qw_counter < 2 && qw_free > 0) {
					uint32_t *qw_data = &packet_data[2 + 4 - qw_counter * 4];
					uint32_t *qw_mask = &packet_mask[2 + 4 - qw_counter * 4];

					qw_data[0] = ntohs(vlan_spec->vlan_tci) << 16 |
						ntohs(vlan_spec->eth_proto);
					qw_data[1] = 0;
					qw_data[2] = 0;
					qw_data[3] = 0;

					qw_mask[0] = ntohs(vlan_mask->vlan_tci) << 16 |
						ntohs(vlan_mask->eth_proto);
					qw_mask[1] = 0;
					qw_mask[2] = 0;
					qw_mask[3] = 0;

					qw_data[0] &= qw_mask[0];
					qw_data[1] &= qw_mask[1];
					qw_data[2] &= qw_mask[2];
					qw_data[3] &= qw_mask[3];

					km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0], 4,
						DYN_FIRST_VLAN, 2 + 4 * fd->vlans);
					set_key_def_qw(key_def, qw_counter, DYN_FIRST_VLAN,
						2 + 4 * fd->vlans);
					qw_counter += 1;
					qw_free -= 1;

				} else {
					NT_LOG(ERR, FILTER,
						"Key size too big. Out of SW-QW resources.");
					flow_nic_set_error(ERR_FAILED, error);
					return -1;
				}

				fd->vlans += 1;
			}

			break;

		case RTE_FLOW_ITEM_TYPE_IPV4:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_IPV4",
				dev->ndev->adapter_no, dev->port);
			{
				const struct rte_flow_item_ipv4 *ipv4_spec =
					(const struct rte_flow_item_ipv4 *)elem[eidx].spec;
				const struct rte_flow_item_ipv4 *ipv4_mask =
					(const struct rte_flow_item_ipv4 *)elem[eidx].mask;

				if (ipv4_spec == NULL || ipv4_mask == NULL) {
					if (any_count > 0 || fd->l3_prot != -1)
						fd->tunnel_l3_prot = PROT_TUN_L3_IPV4;
					else
						fd->l3_prot = PROT_L3_IPV4;
					break;
				}

				if (ipv4_mask->hdr.version_ihl != 0 ||
					ipv4_mask->hdr.type_of_service != 0 ||
					ipv4_mask->hdr.total_length != 0 ||
					ipv4_mask->hdr.packet_id != 0 ||
					(ipv4_mask->hdr.fragment_offset != 0 &&
					(ipv4_spec->hdr.fragment_offset != 0xffff ||
					ipv4_mask->hdr.fragment_offset != 0xffff)) ||
					ipv4_mask->hdr.time_to_live != 0 ||
					ipv4_mask->hdr.hdr_checksum != 0) {
					NT_LOG(ERR, FILTER,
						"Requested IPv4 field not support by running SW version.");
					flow_nic_set_error(ERR_FAILED, error);
					return -1;
				}

				if (ipv4_spec->hdr.fragment_offset == 0xffff &&
					ipv4_mask->hdr.fragment_offset == 0xffff) {
					fd->fragmentation = 0xfe;
				}

				int match_cnt = (ipv4_mask->hdr.src_addr != 0) +
					(ipv4_mask->hdr.dst_addr != 0) +
					(ipv4_mask->hdr.next_proto_id != 0);

				if (match_cnt <= 0) {
					if (any_count > 0 || fd->l3_prot != -1)
						fd->tunnel_l3_prot = PROT_TUN_L3_IPV4;
					else
						fd->l3_prot = PROT_L3_IPV4;
					break;
				}

				if (qw_free > 0 &&
					(match_cnt >= 2 ||
					(match_cnt == 1 && sw_counter >= 2))) {
					if (qw_counter >= 2) {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of QW resources.");
						flow_nic_set_error(ERR_FAILED,
							error);
						return -1;
					}

					uint32_t *qw_data = &packet_data[2 + 4 - qw_counter * 4];
					uint32_t *qw_mask = &packet_mask[2 + 4 - qw_counter * 4];

					qw_mask[0] = 0;
					qw_data[0] = 0;

					qw_mask[1] = ipv4_mask->hdr.next_proto_id << 16;
					qw_data[1] = ipv4_spec->hdr.next_proto_id
						<< 16 & qw_mask[1];

					qw_mask[2] = ntohl(ipv4_mask->hdr.src_addr);
					qw_mask[3] = ntohl(ipv4_mask->hdr.dst_addr);

					qw_data[2] = ntohl(ipv4_spec->hdr.src_addr) & qw_mask[2];
					qw_data[3] = ntohl(ipv4_spec->hdr.dst_addr) & qw_mask[3];

					km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0], 4,
						any_count > 0 ? DYN_TUN_L3 : DYN_L3, 4);
					set_key_def_qw(key_def, qw_counter, any_count > 0
						? DYN_TUN_L3 : DYN_L3, 4);
					qw_counter += 1;
					qw_free -= 1;

					if (any_count > 0 || fd->l3_prot != -1)
						fd->tunnel_l3_prot = PROT_TUN_L3_IPV4;
					else
						fd->l3_prot = PROT_L3_IPV4;
					break;
				}

				if (ipv4_mask->hdr.src_addr) {
					if (sw_counter >= 2) {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of SW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}

					uint32_t *sw_data = &packet_data[1 - sw_counter];
					uint32_t *sw_mask = &packet_mask[1 - sw_counter];

					sw_mask[0] = ntohl(ipv4_mask->hdr.src_addr);
					sw_data[0] = ntohl(ipv4_spec->hdr.src_addr) & sw_mask[0];

					km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1,
						any_count > 0 ? DYN_TUN_L3 : DYN_L3, 12);
					set_key_def_sw(key_def, sw_counter, any_count > 0
						? DYN_TUN_L3 : DYN_L3, 12);
					sw_counter += 1;
				}

				if (ipv4_mask->hdr.dst_addr) {
					if (sw_counter >= 2) {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of SW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}

					uint32_t *sw_data = &packet_data[1 - sw_counter];
					uint32_t *sw_mask = &packet_mask[1 - sw_counter];

					sw_mask[0] = ntohl(ipv4_mask->hdr.dst_addr);
					sw_data[0] = ntohl(ipv4_spec->hdr.dst_addr) & sw_mask[0];

					km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1,
						any_count > 0 ? DYN_TUN_L3 : DYN_L3, 16);
					set_key_def_sw(key_def, sw_counter, any_count > 0
						? DYN_TUN_L3 : DYN_L3, 16);
					sw_counter += 1;
				}

				if (ipv4_mask->hdr.next_proto_id) {
					if (sw_counter >= 2) {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of SW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}

					uint32_t *sw_data = &packet_data[1 - sw_counter];
					uint32_t *sw_mask = &packet_mask[1 - sw_counter];

					sw_mask[0] = ipv4_mask->hdr.next_proto_id << 16;
					sw_data[0] = ipv4_spec->hdr.next_proto_id
						<< 16 & sw_mask[0];

					km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1,
						any_count > 0 ? DYN_TUN_L3 : DYN_L3, 8);
					set_key_def_sw(key_def, sw_counter, any_count > 0
						? DYN_TUN_L3 : DYN_L3, 8);
					sw_counter += 1;
				}

				if (any_count > 0 || fd->l3_prot != -1)
					fd->tunnel_l3_prot = PROT_TUN_L3_IPV4;

				else
					fd->l3_prot = PROT_L3_IPV4;
			}

			break;

		case RTE_FLOW_ITEM_TYPE_IPV6:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_IPV6",
				dev->ndev->adapter_no, dev->port);
			{
				const struct rte_flow_item_ipv6 *ipv6_spec =
					(const struct rte_flow_item_ipv6 *)elem[eidx].spec;
				const struct rte_flow_item_ipv6 *ipv6_mask =
					(const struct rte_flow_item_ipv6 *)elem[eidx].mask;

				if (ipv6_spec == NULL || ipv6_mask == NULL) {
					if (any_count > 0 || fd->l3_prot != -1)
						fd->tunnel_l3_prot = PROT_TUN_L3_IPV6;
					else
						fd->l3_prot = PROT_L3_IPV6;
					break;
				}

				if (ipv6_mask->hdr.vtc_flow != 0 ||
					ipv6_mask->hdr.payload_len != 0 ||
					ipv6_mask->hdr.hop_limits != 0) {
					NT_LOG(ERR, FILTER,
						"Requested IPv6 field not support by running SW version");
					flow_nic_set_error(ERR_FAILED, error);
					return -1;
				}

				if (is_non_zero(&ipv6_spec->hdr.src_addr, 16)) {
					if (qw_counter >= 2) {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of QW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}

					uint32_t *qw_data = &packet_data[2 + 4 - qw_counter * 4];
					uint32_t *qw_mask = &packet_mask[2 + 4 - qw_counter * 4];

					memcpy(&qw_data[0], &ipv6_spec->hdr.src_addr, 16);
					memcpy(&qw_mask[0], &ipv6_mask->hdr.src_addr, 16);

					qw_data[0] = ntohl(qw_data[0]);
					qw_data[1] = ntohl(qw_data[1]);
					qw_data[2] = ntohl(qw_data[2]);
					qw_data[3] = ntohl(qw_data[3]);

					qw_mask[0] = ntohl(qw_mask[0]);
					qw_mask[1] = ntohl(qw_mask[1]);
					qw_mask[2] = ntohl(qw_mask[2]);
					qw_mask[3] = ntohl(qw_mask[3]);

					qw_data[0] &= qw_mask[0];
					qw_data[1] &= qw_mask[1];
					qw_data[2] &= qw_mask[2];
					qw_data[3] &= qw_mask[3];

					km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0], 4,
						any_count > 0 ? DYN_TUN_L3 : DYN_L3, 8);
					set_key_def_qw(key_def, qw_counter, any_count > 0
						? DYN_TUN_L3 : DYN_L3, 8);
					qw_counter += 1;
				}

				if (is_non_zero(&ipv6_spec->hdr.dst_addr, 16)) {
					if (qw_counter >= 2) {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of QW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}

					uint32_t *qw_data = &packet_data[2 + 4 - qw_counter * 4];
					uint32_t *qw_mask = &packet_mask[2 + 4 - qw_counter * 4];

					memcpy(&qw_data[0], &ipv6_spec->hdr.dst_addr, 16);
					memcpy(&qw_mask[0], &ipv6_mask->hdr.dst_addr, 16);

					qw_data[0] = ntohl(qw_data[0]);
					qw_data[1] = ntohl(qw_data[1]);
					qw_data[2] = ntohl(qw_data[2]);
					qw_data[3] = ntohl(qw_data[3]);

					qw_mask[0] = ntohl(qw_mask[0]);
					qw_mask[1] = ntohl(qw_mask[1]);
					qw_mask[2] = ntohl(qw_mask[2]);
					qw_mask[3] = ntohl(qw_mask[3]);

					qw_data[0] &= qw_mask[0];
					qw_data[1] &= qw_mask[1];
					qw_data[2] &= qw_mask[2];
					qw_data[3] &= qw_mask[3];

					km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0], 4,
						any_count > 0 ? DYN_TUN_L3 : DYN_L3, 24);
					set_key_def_qw(key_def, qw_counter, any_count > 0
						? DYN_TUN_L3 : DYN_L3, 24);
					qw_counter += 1;
				}

				if (ipv6_mask->hdr.proto != 0) {
					if (sw_counter < 2) {
						uint32_t *sw_data = &packet_data[1 - sw_counter];
						uint32_t *sw_mask = &packet_mask[1 - sw_counter];

						sw_mask[0] = ipv6_mask->hdr.proto << 8;
						sw_data[0] = ipv6_spec->hdr.proto << 8 & sw_mask[0];

						km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0],
							1, any_count > 0 ? DYN_TUN_L3 : DYN_L3, 4);
						set_key_def_sw(key_def, sw_counter, any_count > 0
							? DYN_TUN_L3 : DYN_L3, 4);
						sw_counter += 1;

					} else if (qw_counter < 2 && qw_free > 0) {
						uint32_t *qw_data =
							&packet_data[2 + 4 - qw_counter * 4];
						uint32_t *qw_mask =
							&packet_mask[2 + 4 - qw_counter * 4];

						qw_data[0] = 0;
						qw_data[1] = ipv6_mask->hdr.proto << 8;
						qw_data[2] = 0;
						qw_data[3] = 0;

						qw_mask[0] = 0;
						qw_mask[1] = ipv6_spec->hdr.proto << 8;
						qw_mask[2] = 0;
						qw_mask[3] = 0;

						qw_data[0] &= qw_mask[0];
						qw_data[1] &= qw_mask[1];
						qw_data[2] &= qw_mask[2];
						qw_data[3] &= qw_mask[3];

						km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0],
							4, any_count > 0 ? DYN_TUN_L3 : DYN_L3, 0);
						set_key_def_qw(key_def, qw_counter, any_count > 0
							? DYN_TUN_L3 : DYN_L3, 0);
						qw_counter += 1;
						qw_free -= 1;

					} else {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of SW-QW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}
				}

				if (any_count > 0 || fd->l3_prot != -1)
					fd->tunnel_l3_prot = PROT_TUN_L3_IPV6;

				else
					fd->l3_prot = PROT_L3_IPV6;
			}

			break;

		case RTE_FLOW_ITEM_TYPE_UDP:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_UDP",
				dev->ndev->adapter_no, dev->port);
			{
				const struct rte_flow_item_udp *udp_spec =
					(const struct rte_flow_item_udp *)elem[eidx].spec;
				const struct rte_flow_item_udp *udp_mask =
					(const struct rte_flow_item_udp *)elem[eidx].mask;

				if (udp_spec == NULL || udp_mask == NULL) {
					if (any_count > 0 || fd->l4_prot != -1) {
						fd->tunnel_l4_prot = PROT_TUN_L4_UDP;
						key_def->inner_proto = 1;
					} else {
						fd->l4_prot = PROT_L4_UDP;
						key_def->outer_proto = 1;
					}
					break;
				}

				if (udp_mask->hdr.dgram_len != 0 ||
					udp_mask->hdr.dgram_cksum != 0) {
					NT_LOG(ERR, FILTER,
						"Requested UDP field not support by running SW version");
					flow_nic_set_error(ERR_FAILED, error);
					return -1;
				}

				if (udp_mask->hdr.src_port || udp_mask->hdr.dst_port) {
					if (sw_counter < 2) {
						uint32_t *sw_data = &packet_data[1 - sw_counter];
						uint32_t *sw_mask = &packet_mask[1 - sw_counter];

						sw_mask[0] = (ntohs(udp_mask->hdr.src_port) << 16) |
							ntohs(udp_mask->hdr.dst_port);
						sw_data[0] = ((ntohs(udp_spec->hdr.src_port)
							<< 16) | ntohs(udp_spec->hdr.dst_port)) &
							sw_mask[0];

						km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0],
							1, any_count > 0 ? DYN_TUN_L4 : DYN_L4, 0);
						set_key_def_sw(key_def, sw_counter, any_count > 0
							? DYN_TUN_L4 : DYN_L4, 0);
						sw_counter += 1;

					} else if (qw_counter < 2 && qw_free > 0) {
						uint32_t *qw_data =
							&packet_data[2 + 4 - qw_counter * 4];
						uint32_t *qw_mask =
							&packet_mask[2 + 4 - qw_counter * 4];

						qw_data[0] = (ntohs(udp_spec->hdr.src_port)
							<< 16) | ntohs(udp_spec->hdr.dst_port);
						qw_data[1] = 0;
						qw_data[2] = 0;
						qw_data[3] = 0;

						qw_mask[0] = (ntohs(udp_mask->hdr.src_port)
							<< 16) | ntohs(udp_mask->hdr.dst_port);
						qw_mask[1] = 0;
						qw_mask[2] = 0;
						qw_mask[3] = 0;

						qw_data[0] &= qw_mask[0];
						qw_data[1] &= qw_mask[1];
						qw_data[2] &= qw_mask[2];
						qw_data[3] &= qw_mask[3];

						km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0],
							4, any_count > 0 ? DYN_TUN_L4 : DYN_L4, 0);
						set_key_def_qw(key_def, qw_counter, any_count > 0
							? DYN_TUN_L4 : DYN_L4, 0);
						qw_counter += 1;
						qw_free -= 1;

					} else {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of SW-QW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}
				}

				if (any_count > 0 || fd->l4_prot != -1) {
					fd->tunnel_l4_prot = PROT_TUN_L4_UDP;
					key_def->inner_proto = 1;

				} else {
					fd->l4_prot = PROT_L4_UDP;
					key_def->outer_proto = 1;
				}
			}

			break;

		case RTE_FLOW_ITEM_TYPE_SCTP:
			NT_LOG(DBG, FILTER, "Adap %i,Port %i:RTE_FLOW_ITEM_TYPE_SCTP",
				dev->ndev->adapter_no, dev->port);
			{
				const struct rte_flow_item_sctp *sctp_spec =
					(const struct rte_flow_item_sctp *)elem[eidx].spec;
				const struct rte_flow_item_sctp *sctp_mask =
					(const struct rte_flow_item_sctp *)elem[eidx].mask;

				if (sctp_spec == NULL || sctp_mask == NULL) {
					if (any_count > 0 || fd->l4_prot != -1) {
						fd->tunnel_l4_prot = PROT_TUN_L4_SCTP;
						key_def->inner_proto = 1;
					} else {
						fd->l4_prot = PROT_L4_SCTP;
						key_def->outer_proto = 1;
					}
					break;
				}

				if (sctp_mask->hdr.tag != 0 || sctp_mask->hdr.cksum != 0) {
					NT_LOG(ERR, FILTER,
						"Requested SCTP field not support by running SW version");
					flow_nic_set_error(ERR_FAILED, error);
					return -1;
				}

				if (sctp_mask->hdr.src_port || sctp_mask->hdr.dst_port) {
					if (sw_counter < 2) {
						uint32_t *sw_data = &packet_data[1 - sw_counter];
						uint32_t *sw_mask = &packet_mask[1 - sw_counter];

						sw_mask[0] = (ntohs(sctp_mask->hdr.src_port)
							<< 16) | ntohs(sctp_mask->hdr.dst_port);
						sw_data[0] = ((ntohs(sctp_spec->hdr.src_port)
							<< 16) | ntohs(sctp_spec->hdr.dst_port)) &
							sw_mask[0];

						km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0],
							1, any_count > 0 ? DYN_TUN_L4 : DYN_L4, 0);
						set_key_def_sw(key_def, sw_counter, any_count > 0
							? DYN_TUN_L4 : DYN_L4, 0);
						sw_counter += 1;

					} else if (qw_counter < 2 && qw_free > 0) {
						uint32_t *qw_data =
							&packet_data[2 + 4 - qw_counter * 4];
						uint32_t *qw_mask =
							&packet_mask[2 + 4 - qw_counter * 4];

						qw_data[0] = (ntohs(sctp_spec->hdr.src_port)
							<< 16) | ntohs(sctp_spec->hdr.dst_port);
						qw_data[1] = 0;
						qw_data[2] = 0;
						qw_data[3] = 0;

						qw_mask[0] = (ntohs(sctp_mask->hdr.src_port)
							<< 16) | ntohs(sctp_mask->hdr.dst_port);
						qw_mask[1] = 0;
						qw_mask[2] = 0;
						qw_mask[3] = 0;

						qw_data[0] &= qw_mask[0];
						qw_data[1] &= qw_mask[1];
						qw_data[2] &= qw_mask[2];
						qw_data[3] &= qw_mask[3];

						km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0],
							4, any_count > 0 ? DYN_TUN_L4 : DYN_L4, 0);
						set_key_def_qw(key_def, qw_counter, any_count > 0
							? DYN_TUN_L4 : DYN_L4, 0);
						qw_counter += 1;
						qw_free -= 1;

					} else {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of SW-QW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}
				}

				if (any_count > 0 || fd->l4_prot != -1) {
					fd->tunnel_l4_prot = PROT_TUN_L4_SCTP;
					key_def->inner_proto = 1;

				} else {
					fd->l4_prot = PROT_L4_SCTP;
					key_def->outer_proto = 1;
				}
			}

			break;

		case RTE_FLOW_ITEM_TYPE_ICMP:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_ICMP",
				dev->ndev->adapter_no, dev->port);
			{
				const struct rte_flow_item_icmp *icmp_spec =
					(const struct rte_flow_item_icmp *)elem[eidx].spec;
				const struct rte_flow_item_icmp *icmp_mask =
					(const struct rte_flow_item_icmp *)elem[eidx].mask;

				if (icmp_spec == NULL || icmp_mask == NULL) {
					if (any_count > 0 || fd->l4_prot != -1) {
						fd->tunnel_l4_prot = PROT_TUN_L4_ICMP;
						fd->tunnel_ip_prot = 1;
						key_def->inner_proto = 1;
					} else {
						fd->l4_prot = PROT_L4_ICMP;
						fd->ip_prot = 1;
						key_def->outer_proto = 1;
					}
					break;
				}

				if (icmp_mask->hdr.icmp_cksum != 0 ||
					icmp_mask->hdr.icmp_ident != 0 ||
					icmp_mask->hdr.icmp_seq_nb != 0) {
					NT_LOG(ERR, FILTER,
						"Requested ICMP field not supported by running SW version");
					flow_nic_set_error(ERR_FAILED, error);
					return -1;
				}

				if (icmp_mask->hdr.icmp_type || icmp_mask->hdr.icmp_code) {
					if (sw_counter < 2) {
						uint32_t *sw_data = &packet_data[1 - sw_counter];
						uint32_t *sw_mask = &packet_mask[1 - sw_counter];

						sw_mask[0] = icmp_mask->hdr.icmp_type << 24 |
							icmp_mask->hdr.icmp_code << 16;
						sw_data[0] = icmp_spec->hdr.icmp_type << 24 |
							icmp_spec->hdr.icmp_code << 16;
						sw_data[0] &= sw_mask[0];

						km_add_match_elem(&fd->km, &sw_data[0],
							&sw_mask[0], 1, any_count > 0
							? DYN_TUN_L4 : DYN_L4, 0);
						set_key_def_sw(key_def, sw_counter,
							any_count > 0 ? DYN_TUN_L4 : DYN_L4, 0);
						sw_counter += 1;

					} else if (qw_counter < 2 && qw_free > 0) {
						uint32_t *qw_data =
							&packet_data[2 + 4 - qw_counter * 4];
						uint32_t *qw_mask =
							&packet_mask[2 + 4 - qw_counter * 4];

						qw_data[0] = icmp_spec->hdr.icmp_type << 24 |
							icmp_spec->hdr.icmp_code << 16;
						qw_data[1] = 0;
						qw_data[2] = 0;
						qw_data[3] = 0;

						qw_mask[0] = icmp_mask->hdr.icmp_type << 24 |
							icmp_mask->hdr.icmp_code << 16;
						qw_mask[1] = 0;
						qw_mask[2] = 0;
						qw_mask[3] = 0;

						qw_data[0] &= qw_mask[0];
						qw_data[1] &= qw_mask[1];
						qw_data[2] &= qw_mask[2];
						qw_data[3] &= qw_mask[3];

						km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0],
							4, any_count > 0 ? DYN_TUN_L4 : DYN_L4, 0);
						set_key_def_qw(key_def, qw_counter, any_count > 0
							? DYN_TUN_L4 : DYN_L4, 0);
						qw_counter += 1;
						qw_free -= 1;

					} else {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of SW-QW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}
				}

				if (any_count > 0 || fd->l4_prot != -1) {
					fd->tunnel_l4_prot = PROT_TUN_L4_ICMP;
					fd->tunnel_ip_prot = 1;
					key_def->inner_proto = 1;

				} else {
					fd->l4_prot = PROT_L4_ICMP;
					fd->ip_prot = 1;
					key_def->outer_proto = 1;
				}
			}

			break;

		case RTE_FLOW_ITEM_TYPE_ICMP6:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_ICMP6",
				dev->ndev->adapter_no, dev->port);
			{
				const struct rte_flow_item_icmp6 *icmp_spec =
					(const struct rte_flow_item_icmp6 *)elem[eidx].spec;
				const struct rte_flow_item_icmp6 *icmp_mask =
					(const struct rte_flow_item_icmp6 *)elem[eidx].mask;

				if (icmp_spec == NULL || icmp_mask == NULL) {
					if (any_count > 0 || fd->l4_prot != -1) {
						fd->tunnel_l4_prot = PROT_TUN_L4_ICMP;
						fd->tunnel_ip_prot = 58;
						key_def->inner_proto = 1;
					} else {
						fd->l4_prot = PROT_L4_ICMP;
						fd->ip_prot = 58;
						key_def->outer_proto = 1;
					}
					break;
				}

				if (icmp_mask->checksum != 0) {
					NT_LOG(ERR, FILTER,
						"Requested ICMP6 field not supported by running SW version");
					flow_nic_set_error(ERR_FAILED, error);
					return -1;
				}

				if (icmp_mask->type || icmp_mask->code) {
					if (sw_counter < 2) {
						uint32_t *sw_data = &packet_data[1 - sw_counter];
						uint32_t *sw_mask = &packet_mask[1 - sw_counter];

						sw_mask[0] = icmp_mask->type << 24 |
							icmp_mask->code << 16;
						sw_data[0] = icmp_spec->type << 24 |
							icmp_spec->code << 16;
						sw_data[0] &= sw_mask[0];

						km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0],
							1, any_count > 0 ? DYN_TUN_L4 : DYN_L4, 0);

						set_key_def_sw(key_def, sw_counter, any_count > 0
							? DYN_TUN_L4 : DYN_L4, 0);
						sw_counter += 1;

					} else if (qw_counter < 2 && qw_free > 0) {
						uint32_t *qw_data =
							&packet_data[2 + 4 - qw_counter * 4];
						uint32_t *qw_mask =
							&packet_mask[2 + 4 - qw_counter * 4];

						qw_data[0] = icmp_spec->type << 24 |
							icmp_spec->code << 16;
						qw_data[1] = 0;
						qw_data[2] = 0;
						qw_data[3] = 0;

						qw_mask[0] = icmp_mask->type << 24 |
							icmp_mask->code << 16;
						qw_mask[1] = 0;
						qw_mask[2] = 0;
						qw_mask[3] = 0;

						qw_data[0] &= qw_mask[0];
						qw_data[1] &= qw_mask[1];
						qw_data[2] &= qw_mask[2];
						qw_data[3] &= qw_mask[3];

						km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0],
							4, any_count > 0 ? DYN_TUN_L4 : DYN_L4, 0);
						set_key_def_qw(key_def, qw_counter, any_count > 0
							? DYN_TUN_L4 : DYN_L4, 0);
						qw_counter += 1;
						qw_free -= 1;

					} else {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of SW-QW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}
				}

				if (any_count > 0 || fd->l4_prot != -1) {
					fd->tunnel_l4_prot = PROT_TUN_L4_ICMP;
					fd->tunnel_ip_prot = 58;
					key_def->inner_proto = 1;

				} else {
					fd->l4_prot = PROT_L4_ICMP;
					fd->ip_prot = 58;
					key_def->outer_proto = 1;
				}
			}

			break;

		case RTE_FLOW_ITEM_TYPE_TCP:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_TCP",
				dev->ndev->adapter_no, dev->port);
			{
				const struct rte_flow_item_tcp *tcp_spec =
					(const struct rte_flow_item_tcp *)elem[eidx].spec;
				const struct rte_flow_item_tcp *tcp_mask =
					(const struct rte_flow_item_tcp *)elem[eidx].mask;

				if (tcp_spec == NULL || tcp_mask == NULL) {
					if (any_count > 0 || fd->l4_prot != -1) {
						fd->tunnel_l4_prot = PROT_TUN_L4_TCP;
						key_def->inner_proto = 1;
					} else {
						fd->l4_prot = PROT_L4_TCP;
						key_def->outer_proto = 1;
					}
					break;
				}

				if (tcp_mask->hdr.sent_seq != 0 ||
					tcp_mask->hdr.recv_ack != 0 ||
					tcp_mask->hdr.data_off != 0 ||
					tcp_mask->hdr.tcp_flags != 0 ||
					tcp_mask->hdr.rx_win != 0 ||
					tcp_mask->hdr.cksum != 0 ||
					tcp_mask->hdr.tcp_urp != 0) {
					NT_LOG(ERR, FILTER,
						"Requested TCP field not support by running SW version");
					flow_nic_set_error(ERR_FAILED, error);
					return -1;
				}

				if (tcp_mask->hdr.src_port || tcp_mask->hdr.dst_port) {
					if (sw_counter < 2) {
						uint32_t *sw_data = &packet_data[1 - sw_counter];
						uint32_t *sw_mask = &packet_mask[1 - sw_counter];

						sw_mask[0] = (ntohs(tcp_mask->hdr.src_port)
							<< 16) | ntohs(tcp_mask->hdr.dst_port);
						sw_data[0] =
							((ntohs(tcp_spec->hdr.src_port) << 16) |
							ntohs(tcp_spec->hdr.dst_port)) & sw_mask[0];

						km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0],
							1, any_count > 0 ? DYN_TUN_L4 : DYN_L4, 0);
						set_key_def_sw(key_def, sw_counter, any_count > 0
							? DYN_TUN_L4 : DYN_L4, 0);
						sw_counter += 1;

					} else if (qw_counter < 2 && qw_free > 0) {
						uint32_t *qw_data =
							&packet_data[2 + 4 - qw_counter * 4];
						uint32_t *qw_mask =
							&packet_mask[2 + 4 - qw_counter * 4];

						qw_data[0] = (ntohs(tcp_spec->hdr.src_port)
							<< 16) | ntohs(tcp_spec->hdr.dst_port);
						qw_data[1] = 0;
						qw_data[2] = 0;
						qw_data[3] = 0;

						qw_mask[0] = (ntohs(tcp_mask->hdr.src_port)
							<< 16) | ntohs(tcp_mask->hdr.dst_port);
						qw_mask[1] = 0;
						qw_mask[2] = 0;
						qw_mask[3] = 0;

						qw_data[0] &= qw_mask[0];
						qw_data[1] &= qw_mask[1];
						qw_data[2] &= qw_mask[2];
						qw_data[3] &= qw_mask[3];

						km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0],
							4, any_count > 0 ? DYN_TUN_L4 : DYN_L4, 0);
						set_key_def_qw(key_def, qw_counter, any_count > 0
							? DYN_TUN_L4 : DYN_L4, 0);
						qw_counter += 1;
						qw_free -= 1;

					} else {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of SW-QW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}
				}

				if (any_count > 0 || fd->l4_prot != -1) {
					fd->tunnel_l4_prot = PROT_TUN_L4_TCP;
					key_def->inner_proto = 1;

				} else {
					fd->l4_prot = PROT_L4_TCP;
					key_def->outer_proto = 1;
				}
			}

			break;

		case RTE_FLOW_ITEM_TYPE_GTP:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_GTP",
				dev->ndev->adapter_no, dev->port);
			{
				const struct rte_gtp_hdr *gtp_spec =
					(const struct rte_gtp_hdr *)elem[eidx].spec;
				const struct rte_gtp_hdr *gtp_mask =
					(const struct rte_gtp_hdr *)elem[eidx].mask;

				if (gtp_spec == NULL || gtp_mask == NULL) {
					fd->tunnel_prot = PROT_TUN_GTPV1U;
					break;
				}

				if (gtp_mask->gtp_hdr_info != 0 ||
					gtp_mask->msg_type != 0 || gtp_mask->plen != 0) {
					NT_LOG(ERR, FILTER,
						"Requested GTP field not support by running SW version");
					flow_nic_set_error(ERR_FAILED, error);
					return -1;
				}

				if (gtp_mask->teid) {
					if (sw_counter < 2) {
						uint32_t *sw_data =
							&packet_data[1 - sw_counter];
						uint32_t *sw_mask =
							&packet_mask[1 - sw_counter];

						sw_mask[0] = ntohl(gtp_mask->teid);
						sw_data[0] =
							ntohl(gtp_spec->teid) & sw_mask[0];

						km_add_match_elem(&fd->km, &sw_data[0],
							&sw_mask[0], 1,
							DYN_L4_PAYLOAD, 4);
						set_key_def_sw(key_def, sw_counter,
							DYN_L4_PAYLOAD, 4);
						sw_counter += 1;

					} else if (qw_counter < 2 && qw_free > 0) {
						uint32_t *qw_data =
							&packet_data[2 + 4 -
							qw_counter * 4];
						uint32_t *qw_mask =
							&packet_mask[2 + 4 -
							qw_counter * 4];

						qw_data[0] = ntohl(gtp_spec->teid);
						qw_data[1] = 0;
						qw_data[2] = 0;
						qw_data[3] = 0;

						qw_mask[0] = ntohl(gtp_mask->teid);
						qw_mask[1] = 0;
						qw_mask[2] = 0;
						qw_mask[3] = 0;

						qw_data[0] &= qw_mask[0];
						qw_data[1] &= qw_mask[1];
						qw_data[2] &= qw_mask[2];
						qw_data[3] &= qw_mask[3];

						km_add_match_elem(&fd->km, &qw_data[0],
							&qw_mask[0], 4,
							DYN_L4_PAYLOAD, 4);
						set_key_def_qw(key_def, qw_counter,
							DYN_L4_PAYLOAD, 4);
						qw_counter += 1;
						qw_free -= 1;

					} else {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of SW-QW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}
				}

				fd->tunnel_prot = PROT_TUN_GTPV1U;
			}

			break;

		case RTE_FLOW_ITEM_TYPE_GTP_PSC:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_GTP_PSC",
				dev->ndev->adapter_no, dev->port);
			{
				const struct rte_gtp_psc_generic_hdr *gtp_psc_spec =
					(const struct rte_gtp_psc_generic_hdr *)elem[eidx].spec;
				const struct rte_gtp_psc_generic_hdr *gtp_psc_mask =
					(const struct rte_gtp_psc_generic_hdr *)elem[eidx].mask;

				if (gtp_psc_spec == NULL || gtp_psc_mask == NULL) {
					fd->tunnel_prot = PROT_TUN_GTPV1U;
					break;
				}

				if (gtp_psc_mask->type != 0 ||
					gtp_psc_mask->ext_hdr_len != 0) {
					NT_LOG(ERR, FILTER,
						"Requested GTP PSC field is not supported by running SW version");
					flow_nic_set_error(ERR_FAILED, error);
					return -1;
				}

				if (gtp_psc_mask->qfi) {
					if (sw_counter < 2) {
						uint32_t *sw_data =
							&packet_data[1 - sw_counter];
						uint32_t *sw_mask =
							&packet_mask[1 - sw_counter];

						sw_mask[0] = ntohl(gtp_psc_mask->qfi);
						sw_data[0] = ntohl(gtp_psc_spec->qfi) &
							sw_mask[0];

						km_add_match_elem(&fd->km, &sw_data[0],
							&sw_mask[0], 1,
							DYN_L4_PAYLOAD, 14);
						set_key_def_sw(key_def, sw_counter,
							DYN_L4_PAYLOAD, 14);
						sw_counter += 1;

					} else if (qw_counter < 2 && qw_free > 0) {
						uint32_t *qw_data =
							&packet_data[2 + 4 -
							qw_counter * 4];
						uint32_t *qw_mask =
							&packet_mask[2 + 4 -
							qw_counter * 4];

						qw_data[0] = ntohl(gtp_psc_spec->qfi);
						qw_data[1] = 0;
						qw_data[2] = 0;
						qw_data[3] = 0;

						qw_mask[0] = ntohl(gtp_psc_mask->qfi);
						qw_mask[1] = 0;
						qw_mask[2] = 0;
						qw_mask[3] = 0;

						qw_data[0] &= qw_mask[0];
						qw_data[1] &= qw_mask[1];
						qw_data[2] &= qw_mask[2];
						qw_data[3] &= qw_mask[3];

						km_add_match_elem(&fd->km, &qw_data[0],
							&qw_mask[0], 4,
							DYN_L4_PAYLOAD, 14);
						set_key_def_qw(key_def, qw_counter,
							DYN_L4_PAYLOAD, 14);
						qw_counter += 1;
						qw_free -= 1;

					} else {
						NT_LOG(ERR, FILTER,
							"Key size too big. Out of SW-QW resources.");
						flow_nic_set_error(ERR_FAILED, error);
						return -1;
					}
				}

				fd->tunnel_prot = PROT_TUN_GTPV1U;
			}

			break;

		case RTE_FLOW_ITEM_TYPE_PORT_ID:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_PORT_ID",
				dev->ndev->adapter_no, dev->port);

			if (elem[eidx].spec) {
				*in_port_id =
					((const struct rte_flow_item_port_id *)elem[eidx].spec)->id;
			}

			break;

		case RTE_FLOW_ITEM_TYPE_VOID:
			NT_LOG(DBG, FILTER, "Adap %i, Port %i: RTE_FLOW_ITEM_TYPE_VOID",
				dev->ndev->adapter_no, dev->port);
			break;

		default:
			NT_LOG(ERR, FILTER, "Invalid or unsupported flow request: %d",
				(int)elem[eidx].type);
			flow_nic_set_error(ERR_MATCH_INVALID_OR_UNSUPPORTED_ELEM, error);
			return -1;
		}
	}

	return 0;
}

static void copy_fd_to_fh_flm(struct flow_handle *fh, const struct nic_flow_def *fd,
	const uint32_t *packet_data, uint32_t flm_key_id, uint32_t flm_ft,
	uint16_t rpl_ext_ptr, uint32_t flm_scrub __rte_unused, uint32_t priority)
{
	switch (fd->l4_prot) {
	case PROT_L4_TCP:
		fh->flm_prot = 6;
		break;

	case PROT_L4_UDP:
		fh->flm_prot = 17;
		break;

	case PROT_L4_SCTP:
		fh->flm_prot = 132;
		break;

	case PROT_L4_ICMP:
		fh->flm_prot = fd->ip_prot;
		break;

	default:
		switch (fd->tunnel_l4_prot) {
		case PROT_TUN_L4_TCP:
			fh->flm_prot = 6;
			break;

		case PROT_TUN_L4_UDP:
			fh->flm_prot = 17;
			break;

		case PROT_TUN_L4_SCTP:
			fh->flm_prot = 132;
			break;

		case PROT_TUN_L4_ICMP:
			fh->flm_prot = fd->tunnel_ip_prot;
			break;

		default:
			fh->flm_prot = 0;
			break;
		}

		break;
	}

	memcpy(fh->flm_data, packet_data, sizeof(uint32_t) * 10);

	fh->flm_kid = flm_key_id;
	fh->flm_rpl_ext_ptr = rpl_ext_ptr;
	fh->flm_prio = (uint8_t)priority;
	fh->flm_ft = (uint8_t)flm_ft;

	for (unsigned int i = 0; i < fd->modify_field_count; ++i) {
		switch (fd->modify_field[i].select) {
		case CPY_SELECT_DSCP_IPV4:
		case CPY_SELECT_RQI_QFI:
			fh->flm_rqi = (fd->modify_field[i].value8[0] >> 6) & 0x1;
			fh->flm_qfi = fd->modify_field[i].value8[0] & 0x3f;
			break;

		case CPY_SELECT_IPV4:
			fh->flm_nat_ipv4 = ntohl(fd->modify_field[i].value32[0]);
			break;

		case CPY_SELECT_PORT:
			fh->flm_nat_port = ntohs(fd->modify_field[i].value16[0]);
			break;

		case CPY_SELECT_TEID:
			fh->flm_teid = ntohl(fd->modify_field[i].value32[0]);
			break;

		default:
			NT_LOG(DBG, FILTER, "Unknown modify field: %d",
				fd->modify_field[i].select);
			break;
		}
	}
}

static int convert_fh_to_fh_flm(struct flow_handle *fh, const uint32_t *packet_data,
	uint32_t flm_key_id, uint32_t flm_ft, uint16_t rpl_ext_ptr,
	uint32_t flm_scrub, uint32_t priority)
{
	struct nic_flow_def *fd;
	struct flow_handle fh_copy;

	if (fh->type != FLOW_HANDLE_TYPE_FLOW)
		return -1;

	memcpy(&fh_copy, fh, sizeof(struct flow_handle));
	memset(fh, 0x0, sizeof(struct flow_handle));
	fd = fh_copy.fd;

	fh->type = FLOW_HANDLE_TYPE_FLM;
	fh->caller_id = fh_copy.caller_id;
	fh->dev = fh_copy.dev;
	fh->next = fh_copy.next;
	fh->prev = fh_copy.prev;
	fh->user_data = fh_copy.user_data;

	fh->flm_db_idx_counter = fh_copy.db_idx_counter;

	for (int i = 0; i < RES_COUNT; ++i)
		fh->flm_db_idxs[i] = fh_copy.db_idxs[i];

	copy_fd_to_fh_flm(fh, fd, packet_data, flm_key_id, flm_ft, rpl_ext_ptr, flm_scrub,
		priority);

	free(fd);

	return 0;
}


static void setup_db_qsl_data(struct nic_flow_def *fd, struct hw_db_inline_qsl_data *qsl_data,
	uint32_t num_dest_port, uint32_t num_queues)
{
	memset(qsl_data, 0x0, sizeof(struct hw_db_inline_qsl_data));

	if (fd->dst_num_avail <= 0) {
		qsl_data->drop = 1;

	} else {
		assert(fd->dst_num_avail < HW_DB_INLINE_MAX_QST_PER_QSL);

		uint32_t ports[fd->dst_num_avail];
		uint32_t queues[fd->dst_num_avail];

		uint32_t port_index = 0;
		uint32_t queue_index = 0;
		uint32_t max = num_dest_port > num_queues ? num_dest_port : num_queues;

		memset(ports, 0, fd->dst_num_avail);
		memset(queues, 0, fd->dst_num_avail);

		qsl_data->table_size = max;
		qsl_data->retransmit = num_dest_port > 0 ? 1 : 0;

		for (int i = 0; i < fd->dst_num_avail; ++i)
			if (fd->dst_id[i].type == PORT_PHY)
				ports[port_index++] = fd->dst_id[i].id;

			else if (fd->dst_id[i].type == PORT_VIRT)
				queues[queue_index++] = fd->dst_id[i].id;

		for (uint32_t i = 0; i < max; ++i) {
			if (num_dest_port > 0) {
				qsl_data->table[i].tx_port = ports[i % num_dest_port];
				qsl_data->table[i].tx_port_en = 1;
			}

			if (num_queues > 0) {
				qsl_data->table[i].queue = queues[i % num_queues];
				qsl_data->table[i].queue_en = 1;
			}
		}
	}
}

static void setup_db_hsh_data(struct nic_flow_def *fd, struct hw_db_inline_hsh_data *hsh_data)
{
	memset(hsh_data, 0x0, sizeof(struct hw_db_inline_hsh_data));

	hsh_data->func = fd->hsh.func;
	hsh_data->hash_mask = fd->hsh.types;

	if (fd->hsh.key != NULL) {
		/*
		 * Just a safeguard. Check and error handling of rss_key_len
		 * shall be done at api layers above.
		 */
		memcpy(&hsh_data->key, fd->hsh.key,
			fd->hsh.key_len < MAX_RSS_KEY_LEN ? fd->hsh.key_len : MAX_RSS_KEY_LEN);
	}
}

static int setup_flow_flm_actions(struct flow_eth_dev *dev,
	const struct nic_flow_def *fd,
	const struct hw_db_inline_qsl_data *qsl_data,
	const struct hw_db_inline_hsh_data *hsh_data,
	uint32_t group __rte_unused,
	uint32_t local_idxs[],
	uint32_t *local_idx_counter,
	uint16_t *flm_rpl_ext_ptr __rte_unused,
	uint32_t *flm_ft __rte_unused,
	uint32_t *flm_scrub __rte_unused,
	struct rte_flow_error *error)
{
	const bool empty_pattern = fd_has_empty_pattern(fd);

	/* Setup COT */
	struct hw_db_inline_cot_data cot_data = {
		.matcher_color_contrib = empty_pattern ? 0x0 : 0x4,	/* FT key C */
		.frag_rcp = 0,
	};
	struct hw_db_cot_idx cot_idx =
		hw_db_inline_cot_add(dev->ndev, dev->ndev->hw_db_handle, &cot_data);
	local_idxs[(*local_idx_counter)++] = cot_idx.raw;

	if (cot_idx.error) {
		NT_LOG(ERR, FILTER, "Could not reference COT resource");
		flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
		return -1;
	}

	/* Finalize QSL */
	struct hw_db_qsl_idx qsl_idx =
		hw_db_inline_qsl_add(dev->ndev, dev->ndev->hw_db_handle, qsl_data);
	local_idxs[(*local_idx_counter)++] = qsl_idx.raw;

	if (qsl_idx.error) {
		NT_LOG(ERR, FILTER, "Could not reference QSL resource");
		flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
		return -1;
	}

	/* Setup HSH */
	struct hw_db_hsh_idx hsh_idx =
		hw_db_inline_hsh_add(dev->ndev, dev->ndev->hw_db_handle, hsh_data);
	local_idxs[(*local_idx_counter)++] = hsh_idx.raw;

	if (hsh_idx.error) {
		NT_LOG(ERR, FILTER, "Could not reference HSH resource");
		flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
		return -1;
	}

	/* Setup SLC LR */
	struct hw_db_slc_lr_idx slc_lr_idx = { .raw = 0 };

	if (fd->header_strip_end_dyn != 0 || fd->header_strip_end_ofs != 0) {
		struct hw_db_inline_slc_lr_data slc_lr_data = {
			.head_slice_en = 1,
			.head_slice_dyn = fd->header_strip_end_dyn,
			.head_slice_ofs = fd->header_strip_end_ofs,
		};
		slc_lr_idx =
			hw_db_inline_slc_lr_add(dev->ndev, dev->ndev->hw_db_handle, &slc_lr_data);
		local_idxs[(*local_idx_counter)++] = slc_lr_idx.raw;

		if (slc_lr_idx.error) {
			NT_LOG(ERR, FILTER, "Could not reference SLC LR resource");
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
			return -1;
		}
	}

	/* Setup TPE EXT */
	if (fd->tun_hdr.len > 0) {
		assert(fd->tun_hdr.len <= HW_DB_INLINE_MAX_ENCAP_SIZE);

		struct hw_db_inline_tpe_ext_data tpe_ext_data = {
			.size = fd->tun_hdr.len,
		};

		memset(tpe_ext_data.hdr8, 0x0, HW_DB_INLINE_MAX_ENCAP_SIZE);
		memcpy(tpe_ext_data.hdr8, fd->tun_hdr.d.hdr8, (fd->tun_hdr.len + 15) & ~15);

		struct hw_db_tpe_ext_idx tpe_ext_idx =
			hw_db_inline_tpe_ext_add(dev->ndev, dev->ndev->hw_db_handle,
			&tpe_ext_data);
		local_idxs[(*local_idx_counter)++] = tpe_ext_idx.raw;

		if (tpe_ext_idx.error) {
			NT_LOG(ERR, FILTER, "Could not reference TPE EXT resource");
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
			return -1;
		}

		if (flm_rpl_ext_ptr)
			*flm_rpl_ext_ptr = tpe_ext_idx.ids;
	}

	/* Setup TPE */
	assert(fd->modify_field_count <= 6);

	struct hw_db_inline_tpe_data tpe_data = {
		.insert_len = fd->tun_hdr.len,
		.new_outer = fd->tun_hdr.new_outer,
		.calc_eth_type_from_inner_ip =
			!fd->tun_hdr.new_outer && fd->header_strip_end_dyn == DYN_TUN_L3,
		.ttl_en = fd->ttl_sub_enable,
		.ttl_dyn = fd->ttl_sub_outer ? DYN_L3 : DYN_TUN_L3,
		.ttl_ofs = fd->ttl_sub_ipv4 ? 8 : 7,
	};

	for (unsigned int i = 0; i < fd->modify_field_count; ++i) {
		tpe_data.writer[i].en = 1;
		tpe_data.writer[i].reader_select = fd->modify_field[i].select;
		tpe_data.writer[i].dyn = fd->modify_field[i].dyn;
		tpe_data.writer[i].ofs = fd->modify_field[i].ofs;
		tpe_data.writer[i].len = fd->modify_field[i].len;
	}

	if (fd->tun_hdr.new_outer) {
		const int fcs_length = 4;

		/* L4 length */
		tpe_data.len_a_en = 1;
		tpe_data.len_a_pos_dyn = DYN_L4;
		tpe_data.len_a_pos_ofs = 4;
		tpe_data.len_a_add_dyn = 18;
		tpe_data.len_a_add_ofs = (uint32_t)(-fcs_length) & 0xff;
		tpe_data.len_a_sub_dyn = DYN_L4;

		/* L3 length */
		tpe_data.len_b_en = 1;
		tpe_data.len_b_pos_dyn = DYN_L3;
		tpe_data.len_b_pos_ofs = fd->tun_hdr.ip_version == 4 ? 2 : 4;
		tpe_data.len_b_add_dyn = 18;
		tpe_data.len_b_add_ofs = (uint32_t)(-fcs_length) & 0xff;
		tpe_data.len_b_sub_dyn = DYN_L3;

		/* GTP length */
		tpe_data.len_c_en = 1;
		tpe_data.len_c_pos_dyn = DYN_L4_PAYLOAD;
		tpe_data.len_c_pos_ofs = 2;
		tpe_data.len_c_add_dyn = 18;
		tpe_data.len_c_add_ofs = (uint32_t)(-8 - fcs_length) & 0xff;
		tpe_data.len_c_sub_dyn = DYN_L4_PAYLOAD;
	}

	struct hw_db_tpe_idx tpe_idx =
		hw_db_inline_tpe_add(dev->ndev, dev->ndev->hw_db_handle, &tpe_data);

	local_idxs[(*local_idx_counter)++] = tpe_idx.raw;

	if (tpe_idx.error) {
		NT_LOG(ERR, FILTER, "Could not reference TPE resource");
		flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
		return -1;
	}

	return 0;
}

static struct flow_handle *create_flow_filter(struct flow_eth_dev *dev, struct nic_flow_def *fd,
	const struct rte_flow_attr *attr,
	uint16_t forced_vlan_vid __rte_unused, uint16_t caller_id,
	struct rte_flow_error *error, uint32_t port_id,
	uint32_t num_dest_port __rte_unused, uint32_t num_queues __rte_unused,
	uint32_t *packet_data, uint32_t *packet_mask __rte_unused,
	struct flm_flow_key_def_s *key_def __rte_unused)
{
	struct flow_handle *fh = calloc(1, sizeof(struct flow_handle));

	fh->type = FLOW_HANDLE_TYPE_FLOW;
	fh->port_id = port_id;
	fh->dev = dev;
	fh->fd = fd;
	fh->caller_id = caller_id;

	struct hw_db_inline_qsl_data qsl_data;
	setup_db_qsl_data(fd, &qsl_data, num_dest_port, num_queues);

	struct hw_db_inline_hsh_data hsh_data;
	setup_db_hsh_data(fd, &hsh_data);

	if (attr->group > 0 && fd_has_empty_pattern(fd)) {
		/*
		 * Default flow for group 1..32
		 */

		if (setup_flow_flm_actions(dev, fd, &qsl_data, &hsh_data, attr->group, fh->db_idxs,
			&fh->db_idx_counter, NULL, NULL, NULL, error)) {
			goto error_out;
		}

		nic_insert_flow(dev->ndev, fh);

	} else if (attr->group > 0) {
		/*
		 * Flow for group 1..32
		 */

		/* Setup Actions */
		uint16_t flm_rpl_ext_ptr = 0;
		uint32_t flm_ft = 0;
		uint32_t flm_scrub = 0;

		if (setup_flow_flm_actions(dev, fd, &qsl_data, &hsh_data, attr->group, fh->db_idxs,
			&fh->db_idx_counter, &flm_rpl_ext_ptr, &flm_ft,
			&flm_scrub, error)) {
			goto error_out;
		}

		/* Program flow */
		convert_fh_to_fh_flm(fh, packet_data, 2, flm_ft, flm_rpl_ext_ptr,
			flm_scrub, attr->priority & 0x3);
		flm_flow_programming(fh, NT_FLM_OP_LEARN);

		nic_insert_flow_flm(dev->ndev, fh);

	} else {
		/*
		 * Flow for group 0
		 */
		int identical_km_entry_ft = -1;

		struct hw_db_inline_action_set_data action_set_data = { 0 };
		(void)action_set_data;

		if (fd->jump_to_group != UINT32_MAX) {
			/* Action Set only contains jump */
			action_set_data.contains_jump = 1;
			action_set_data.jump = fd->jump_to_group;

		} else {
			/* Action Set doesn't contain jump */
			action_set_data.contains_jump = 0;

			/* Setup COT */
			struct hw_db_inline_cot_data cot_data = {
				.matcher_color_contrib = 0,
				.frag_rcp = 0,
			};
			struct hw_db_cot_idx cot_idx =
				hw_db_inline_cot_add(dev->ndev, dev->ndev->hw_db_handle,
				&cot_data);
			fh->db_idxs[fh->db_idx_counter++] = cot_idx.raw;
			action_set_data.cot = cot_idx;

			if (cot_idx.error) {
				NT_LOG(ERR, FILTER, "Could not reference COT resource");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
				goto error_out;
			}

			/* Finalize QSL */
			struct hw_db_qsl_idx qsl_idx =
				hw_db_inline_qsl_add(dev->ndev, dev->ndev->hw_db_handle,
				&qsl_data);
			fh->db_idxs[fh->db_idx_counter++] = qsl_idx.raw;
			action_set_data.qsl = qsl_idx;

			if (qsl_idx.error) {
				NT_LOG(ERR, FILTER, "Could not reference QSL resource");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
				goto error_out;
			}

			/* Setup HSH */
			struct hw_db_hsh_idx hsh_idx =
				hw_db_inline_hsh_add(dev->ndev, dev->ndev->hw_db_handle,
				&hsh_data);
			fh->db_idxs[fh->db_idx_counter++] = hsh_idx.raw;
			action_set_data.hsh = hsh_idx;

			if (hsh_idx.error) {
				NT_LOG(ERR, FILTER, "Could not reference HSH resource");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
				goto error_out;
			}

			/* Setup TPE */
			if (fd->ttl_sub_enable) {
				struct hw_db_inline_tpe_data tpe_data = {
					.insert_len = fd->tun_hdr.len,
					.new_outer = fd->tun_hdr.new_outer,
					.calc_eth_type_from_inner_ip = !fd->tun_hdr.new_outer &&
						fd->header_strip_end_dyn == DYN_TUN_L3,
					.ttl_en = fd->ttl_sub_enable,
					.ttl_dyn = fd->ttl_sub_outer ? DYN_L3 : DYN_TUN_L3,
					.ttl_ofs = fd->ttl_sub_ipv4 ? 8 : 7,
				};
				struct hw_db_tpe_idx tpe_idx =
					hw_db_inline_tpe_add(dev->ndev, dev->ndev->hw_db_handle,
					&tpe_data);
				fh->db_idxs[fh->db_idx_counter++] = tpe_idx.raw;
				action_set_data.tpe = tpe_idx;

				if (tpe_idx.error) {
					NT_LOG(ERR, FILTER, "Could not reference TPE resource");
					flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
					goto error_out;
				}
			}
		}

		/* Setup CAT */
		struct hw_db_inline_cat_data cat_data = {
			.vlan_mask = (0xf << fd->vlans) & 0xf,
			.mac_port_mask = 1 << fh->port_id,
			.ptc_mask_frag = fd->fragmentation,
			.ptc_mask_l2 = fd->l2_prot != -1 ? (1 << fd->l2_prot) : -1,
			.ptc_mask_l3 = fd->l3_prot != -1 ? (1 << fd->l3_prot) : -1,
			.ptc_mask_l4 = fd->l4_prot != -1 ? (1 << fd->l4_prot) : -1,
			.err_mask_ttl = (fd->ttl_sub_enable &&
				fd->ttl_sub_outer) ? -1 : 0x1,
			.ptc_mask_tunnel = fd->tunnel_prot !=
				-1 ? (1 << fd->tunnel_prot) : -1,
			.ptc_mask_l3_tunnel =
				fd->tunnel_l3_prot != -1 ? (1 << fd->tunnel_l3_prot) : -1,
			.ptc_mask_l4_tunnel =
				fd->tunnel_l4_prot != -1 ? (1 << fd->tunnel_l4_prot) : -1,
			.err_mask_ttl_tunnel =
				(fd->ttl_sub_enable && !fd->ttl_sub_outer) ? -1 : 0x1,
			.ip_prot = fd->ip_prot,
			.ip_prot_tunnel = fd->tunnel_ip_prot,
		};
		struct hw_db_cat_idx cat_idx =
			hw_db_inline_cat_add(dev->ndev, dev->ndev->hw_db_handle, &cat_data);
		fh->db_idxs[fh->db_idx_counter++] = cat_idx.raw;

		if (cat_idx.error) {
			NT_LOG(ERR, FILTER, "Could not reference CAT resource");
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
			goto error_out;
		}

		/* Setup KM RCP */
		struct hw_db_inline_km_rcp_data km_rcp_data = { .rcp = 0 };

		if (fd->km.num_ftype_elem) {
			struct flow_handle *flow = dev->ndev->flow_base, *found_flow = NULL;

			if (km_key_create(&fd->km, fh->port_id)) {
				NT_LOG(ERR, FILTER, "KM creation failed");
				flow_nic_set_error(ERR_MATCH_FAILED_BY_HW_LIMITS, error);
				goto error_out;
			}

			fd->km.be = &dev->ndev->be;

			/* Look for existing KM RCPs */
			while (flow) {
				if (flow->type == FLOW_HANDLE_TYPE_FLOW &&
					flow->fd->km.flow_type) {
					int res = km_key_compare(&fd->km, &flow->fd->km);

					if (res < 0) {
						/* Flow rcp and match data is identical */
						identical_km_entry_ft = flow->fd->km.flow_type;
						found_flow = flow;
						break;
					}

					if (res > 0) {
						/* Flow rcp found and match data is different */
						found_flow = flow;
					}
				}

				flow = flow->next;
			}

			km_attach_ndev_resource_management(&fd->km, &dev->ndev->km_res_handle);

			if (found_flow != NULL) {
				/* Reuse existing KM RCP */
				const struct hw_db_inline_km_rcp_data *other_km_rcp_data =
					hw_db_inline_find_data(dev->ndev, dev->ndev->hw_db_handle,
					HW_DB_IDX_TYPE_KM_RCP,
					(struct hw_db_idx *)
					found_flow->flm_db_idxs,
					found_flow->flm_db_idx_counter);

				if (other_km_rcp_data == NULL ||
					flow_nic_ref_resource(dev->ndev, RES_KM_CATEGORY,
					other_km_rcp_data->rcp)) {
					NT_LOG(ERR, FILTER,
						"Could not reference existing KM RCP resource");
					flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
					goto error_out;
				}

				km_rcp_data.rcp = other_km_rcp_data->rcp;
			} else {
				/* Alloc new KM RCP */
				int rcp = flow_nic_alloc_resource(dev->ndev, RES_KM_CATEGORY, 1);

				if (rcp < 0) {
					NT_LOG(ERR, FILTER,
						"Could not reference KM RCP resource (flow_nic_alloc)");
					flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
					goto error_out;
				}

				km_rcp_set(&fd->km, rcp);
				km_rcp_data.rcp = (uint32_t)rcp;
			}
		}

		struct hw_db_km_idx km_idx =
			hw_db_inline_km_add(dev->ndev, dev->ndev->hw_db_handle, &km_rcp_data);

		fh->db_idxs[fh->db_idx_counter++] = km_idx.raw;

		if (km_idx.error) {
			NT_LOG(ERR, FILTER, "Could not reference KM RCP resource (db_inline)");
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
			goto error_out;
		}

		/* Setup KM FT */
		struct hw_db_inline_km_ft_data km_ft_data = {
			.cat = cat_idx,
			.km = km_idx,
		};
		struct hw_db_km_ft km_ft_idx =
			hw_db_inline_km_ft_add(dev->ndev, dev->ndev->hw_db_handle, &km_ft_data);
		fh->db_idxs[fh->db_idx_counter++] = km_ft_idx.raw;

		if (km_ft_idx.error) {
			NT_LOG(ERR, FILTER, "Could not reference KM FT resource");
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
			goto error_out;
		}

		/* Finalize KM RCP */
		if (fd->km.num_ftype_elem) {
			if (identical_km_entry_ft >= 0 && identical_km_entry_ft != km_ft_idx.id1) {
				NT_LOG(ERR, FILTER,
					"Identical KM matches cannot have different KM FTs");
				flow_nic_set_error(ERR_MATCH_FAILED_BY_HW_LIMITS, error);
				goto error_out;
			}

			fd->km.flow_type = km_ft_idx.id1;

			if (fd->km.target == KM_CAM) {
				uint32_t ft_a_mask = 0;
				hw_mod_km_rcp_get(&dev->ndev->be, HW_KM_RCP_FTM_A,
					(int)km_rcp_data.rcp, 0, &ft_a_mask);
				hw_mod_km_rcp_set(&dev->ndev->be, HW_KM_RCP_FTM_A,
					(int)km_rcp_data.rcp, 0,
					ft_a_mask | (1 << fd->km.flow_type));
			}

			hw_mod_km_rcp_flush(&dev->ndev->be, (int)km_rcp_data.rcp, 1);

			km_write_data_match_entry(&fd->km, 0);
		}

		nic_insert_flow(dev->ndev, fh);
	}

	return fh;

error_out:

	if (fh->type == FLOW_HANDLE_TYPE_FLM) {
		hw_db_inline_deref_idxs(dev->ndev, dev->ndev->hw_db_handle,
			(struct hw_db_idx *)fh->flm_db_idxs,
			fh->flm_db_idx_counter);

	} else {
		hw_db_inline_deref_idxs(dev->ndev, dev->ndev->hw_db_handle,
			(struct hw_db_idx *)fh->db_idxs, fh->db_idx_counter);
	}

	free(fh);

	return NULL;
}

/*
 * FPGA uses up to 10 32-bit words (320 bits) for hash calculation + 8 bits for L4 protocol number.
 * Hashed data are split between two 128-bit Quad Words (QW)
 * and two 32-bit Words (W), which can refer to different header parts.
 */
enum hsh_words_id {
	HSH_WORDS_QW0 = 0,
	HSH_WORDS_QW4,
	HSH_WORDS_W8,
	HSH_WORDS_W9,
	HSH_WORDS_SIZE,
};

/* struct with details about hash QWs & Ws */
struct hsh_words {
	/*
	 * index of W (word) or index of 1st word of QW (quad word)
	 * is used for hash mask calculation
	 */
	uint8_t index;
	uint8_t toeplitz_index;	/* offset in Bytes of given [Q]W inside Toeplitz RSS key */
	enum hw_hsh_e pe;	/* offset to header part, e.g. beginning of L4 */
	enum hw_hsh_e ofs;	/* relative offset in BYTES to 'pe' header offset above */
	uint16_t bit_len;	/* max length of header part in bits to fit into QW/W */
	bool free;	/* only free words can be used for hsh calculation */
};

static enum hsh_words_id get_free_word(struct hsh_words *words, uint16_t bit_len)
{
	enum hsh_words_id ret = HSH_WORDS_SIZE;
	uint16_t ret_bit_len = UINT16_MAX;

	for (enum hsh_words_id i = HSH_WORDS_QW0; i < HSH_WORDS_SIZE; i++) {
		if (words[i].free && bit_len <= words[i].bit_len &&
			words[i].bit_len < ret_bit_len) {
			ret = i;
			ret_bit_len = words[i].bit_len;
		}
	}

	return ret;
}

static int flow_nic_set_hasher_part_inline(struct flow_nic_dev *ndev, int hsh_idx,
	struct hsh_words *words, uint32_t pe, uint32_t ofs,
	int bit_len, bool toeplitz)
{
	int res = 0;

	/* check if there is any free word, which can accommodate header part of given 'bit_len' */
	enum hsh_words_id word = get_free_word(words, bit_len);

	if (word == HSH_WORDS_SIZE) {
		NT_LOG(ERR, FILTER, "Cannot add additional %d bits into hash", bit_len);
		return -1;
	}

	words[word].free = false;

	res |= hw_mod_hsh_rcp_set(&ndev->be, words[word].pe, hsh_idx, 0, pe);
	NT_LOG(DBG, FILTER, "hw_mod_hsh_rcp_set(&ndev->be, %d, %d, 0, %d)", words[word].pe,
		hsh_idx, pe);
	res |= hw_mod_hsh_rcp_set(&ndev->be, words[word].ofs, hsh_idx, 0, ofs);
	NT_LOG(DBG, FILTER, "hw_mod_hsh_rcp_set(&ndev->be, %d, %d, 0, %d)", words[word].ofs,
		hsh_idx, ofs);

	/* set HW_HSH_RCP_WORD_MASK based on used QW/W and given 'bit_len' */
	int mask_bit_len = bit_len;
	uint32_t mask = 0x0;
	uint32_t mask_be = 0x0;
	uint32_t toeplitz_mask[9] = { 0x0 };
	/* iterate through all words of QW */
	uint16_t words_count = words[word].bit_len / 32;

	for (uint16_t mask_off = 1; mask_off <= words_count; mask_off++) {
		if (mask_bit_len >= 32) {
			mask_bit_len -= 32;
			mask = 0xffffffff;
			mask_be = mask;

		} else if (mask_bit_len > 0) {
			/* keep bits from left to right, i.e. little to big endian */
			mask_be = 0xffffffff >> (32 - mask_bit_len);
			mask = mask_be << (32 - mask_bit_len);
			mask_bit_len = 0;

		} else {
			mask = 0x0;
			mask_be = 0x0;
		}

		/* reorder QW words mask from little to big endian */
		res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, hsh_idx,
			words[word].index + words_count - mask_off, mask);
		NT_LOG(DBG, FILTER,
			"hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_WORD_MASK, %d, %d, 0x%" PRIX32
			")",
			hsh_idx, words[word].index + words_count - mask_off, mask);
		toeplitz_mask[words[word].toeplitz_index + mask_off - 1] = mask_be;
	}

	if (toeplitz) {
		NT_LOG(DBG, FILTER,
			"Partial Toeplitz RSS key mask: %08" PRIX32 " %08" PRIX32 " %08" PRIX32
			" %08" PRIX32 " %08" PRIX32 " %08" PRIX32 " %08" PRIX32 " %08" PRIX32
			" %08" PRIX32 "",
			toeplitz_mask[8], toeplitz_mask[7], toeplitz_mask[6], toeplitz_mask[5],
			toeplitz_mask[4], toeplitz_mask[3], toeplitz_mask[2], toeplitz_mask[1],
			toeplitz_mask[0]);
		NT_LOG(DBG, FILTER,
			"                               MSB                                                                          LSB");
	}

	return res;
}

/*
 * Public functions
 */

int initialize_flow_management_of_ndev_profile_inline(struct flow_nic_dev *ndev)
{
	if (!ndev->flow_mgnt_prepared) {
		/* Check static arrays are big enough */
		assert(ndev->be.tpe.nb_cpy_writers <= MAX_CPY_WRITERS_SUPPORTED);
		/* KM Flow Type 0 is reserved */
		flow_nic_mark_resource_used(ndev, RES_KM_FLOW_TYPE, 0);
		flow_nic_mark_resource_used(ndev, RES_KM_CATEGORY, 0);

		/* Reserved FLM Flow Types */
		flow_nic_mark_resource_used(ndev, RES_FLM_FLOW_TYPE, NT_FLM_MISS_FLOW_TYPE);
		flow_nic_mark_resource_used(ndev, RES_FLM_FLOW_TYPE, NT_FLM_UNHANDLED_FLOW_TYPE);
		flow_nic_mark_resource_used(ndev, RES_FLM_FLOW_TYPE,
			NT_FLM_VIOLATING_MBR_FLOW_TYPE);
		flow_nic_mark_resource_used(ndev, RES_FLM_RCP, 0);

		/* COT is locked to CFN. Don't set color for CFN 0 */
		hw_mod_cat_cot_set(&ndev->be, HW_CAT_COT_PRESET_ALL, 0, 0);

		if (hw_mod_cat_cot_flush(&ndev->be, 0, 1) < 0)
			goto err_exit0;

		/* Initialize QSL with unmatched recipe index 0 - discard */
		if (hw_mod_qsl_rcp_set(&ndev->be, HW_QSL_RCP_DISCARD, 0, 0x1) < 0)
			goto err_exit0;

		if (hw_mod_qsl_rcp_flush(&ndev->be, 0, 1) < 0)
			goto err_exit0;

		flow_nic_mark_resource_used(ndev, RES_QSL_RCP, 0);

		/* Initialize QST with default index 0 */
		if (hw_mod_qsl_qst_set(&ndev->be, HW_QSL_QST_PRESET_ALL, 0, 0x0) < 0)
			goto err_exit0;

		if (hw_mod_qsl_qst_flush(&ndev->be, 0, 1) < 0)
			goto err_exit0;

		flow_nic_mark_resource_used(ndev, RES_QSL_QST, 0);

		/* SLC LR & TPE index 0 were reserved */
		flow_nic_mark_resource_used(ndev, RES_SLC_LR_RCP, 0);
		flow_nic_mark_resource_used(ndev, RES_TPE_RCP, 0);
		flow_nic_mark_resource_used(ndev, RES_TPE_EXT, 0);
		flow_nic_mark_resource_used(ndev, RES_TPE_RPL, 0);

		/* PDB setup Direct Virtio Scatter-Gather descriptor of 12 bytes for its recipe 0
		 */
		if (hw_mod_pdb_rcp_set(&ndev->be, HW_PDB_RCP_DESCRIPTOR, 0, 7) < 0)
			goto err_exit0;

		if (hw_mod_pdb_rcp_set(&ndev->be, HW_PDB_RCP_DESC_LEN, 0, 6) < 0)
			goto err_exit0;

		if (hw_mod_pdb_rcp_flush(&ndev->be, 0, 1) < 0)
			goto err_exit0;

		flow_nic_mark_resource_used(ndev, RES_PDB_RCP, 0);

		/* Set default hasher recipe to 5-tuple */
		flow_nic_set_hasher(ndev, 0, HASH_ALGO_5TUPLE);
		hw_mod_hsh_rcp_flush(&ndev->be, 0, 1);

		flow_nic_mark_resource_used(ndev, RES_HSH_RCP, 0);

		/* Setup filter using matching all packets violating traffic policing parameters */
		flow_nic_mark_resource_used(ndev, RES_CAT_CFN, NT_VIOLATING_MBR_CFN);
		flow_nic_mark_resource_used(ndev, RES_QSL_RCP, NT_VIOLATING_MBR_QSL);

		if (hw_db_inline_setup_mbr_filter(ndev, NT_VIOLATING_MBR_CFN,
			NT_FLM_VIOLATING_MBR_FLOW_TYPE,
			NT_VIOLATING_MBR_QSL) < 0)
			goto err_exit0;

		ndev->id_table_handle = ntnic_id_table_create();

		if (ndev->id_table_handle == NULL)
			goto err_exit0;

		if (flow_group_handle_create(&ndev->group_handle, ndev->be.flm.nb_categories))
			goto err_exit0;

		if (hw_db_inline_create(ndev, &ndev->hw_db_handle))
			goto err_exit0;

		ndev->flow_mgnt_prepared = 1;
	}

	return 0;

err_exit0:
	done_flow_management_of_ndev_profile_inline(ndev);
	return -1;
}

int done_flow_management_of_ndev_profile_inline(struct flow_nic_dev *ndev)
{
#ifdef FLOW_DEBUG
	ndev->be.iface->set_debug_mode(ndev->be.be_dev, FLOW_BACKEND_DEBUG_MODE_WRITE);
#endif

	if (ndev->flow_mgnt_prepared) {
		flow_nic_free_resource(ndev, RES_KM_FLOW_TYPE, 0);
		flow_nic_free_resource(ndev, RES_KM_CATEGORY, 0);

		flow_group_handle_destroy(&ndev->group_handle);
		ntnic_id_table_destroy(ndev->id_table_handle);

		hw_mod_cat_cfn_set(&ndev->be, HW_CAT_CFN_PRESET_ALL, 0, 0, 0);
		hw_mod_cat_cfn_flush(&ndev->be, 0, 1);
		hw_mod_cat_cot_set(&ndev->be, HW_CAT_COT_PRESET_ALL, 0, 0);
		hw_mod_cat_cot_flush(&ndev->be, 0, 1);
		flow_nic_free_resource(ndev, RES_CAT_CFN, 0);

		hw_mod_qsl_rcp_set(&ndev->be, HW_QSL_RCP_PRESET_ALL, 0, 0);
		hw_mod_qsl_rcp_flush(&ndev->be, 0, 1);
		flow_nic_free_resource(ndev, RES_QSL_RCP, 0);

		hw_mod_slc_lr_rcp_set(&ndev->be, HW_SLC_LR_RCP_PRESET_ALL, 0, 0);
		hw_mod_slc_lr_rcp_flush(&ndev->be, 0, 1);
		flow_nic_free_resource(ndev, RES_SLC_LR_RCP, 0);

		hw_mod_tpe_reset(&ndev->be);
		flow_nic_free_resource(ndev, RES_TPE_RCP, 0);
		flow_nic_free_resource(ndev, RES_TPE_EXT, 0);
		flow_nic_free_resource(ndev, RES_TPE_RPL, 0);

		hw_mod_pdb_rcp_set(&ndev->be, HW_PDB_RCP_PRESET_ALL, 0, 0);
		hw_mod_pdb_rcp_flush(&ndev->be, 0, 1);
		flow_nic_free_resource(ndev, RES_PDB_RCP, 0);

		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_PRESET_ALL, 0, 0, 0);
		hw_mod_hsh_rcp_flush(&ndev->be, 0, 1);
		flow_nic_free_resource(ndev, RES_HSH_RCP, 0);

		hw_db_inline_destroy(ndev->hw_db_handle);

#ifdef FLOW_DEBUG
		ndev->be.iface->set_debug_mode(ndev->be.be_dev, FLOW_BACKEND_DEBUG_MODE_NONE);
#endif

		ndev->flow_mgnt_prepared = 0;
	}

	return 0;
}

struct flow_handle *flow_create_profile_inline(struct flow_eth_dev *dev __rte_unused,
	const struct rte_flow_attr *attr __rte_unused,
	uint16_t forced_vlan_vid __rte_unused,
	uint16_t caller_id __rte_unused,
	const struct rte_flow_item elem[] __rte_unused,
	const struct rte_flow_action action[] __rte_unused,
	struct rte_flow_error *error __rte_unused)
{
	struct flow_handle *fh = NULL;
	int res;

	uint32_t port_id = UINT32_MAX;
	uint32_t num_dest_port;
	uint32_t num_queues;

	uint32_t packet_data[10];
	uint32_t packet_mask[10];
	struct flm_flow_key_def_s key_def;

	struct rte_flow_attr attr_local;
	memcpy(&attr_local, attr, sizeof(struct rte_flow_attr));
	uint16_t forced_vlan_vid_local = forced_vlan_vid;
	uint16_t caller_id_local = caller_id;

	if (attr_local.group > 0)
		forced_vlan_vid_local = 0;

	flow_nic_set_error(ERR_SUCCESS, error);

	struct nic_flow_def *fd = allocate_nic_flow_def();

	if (fd == NULL)
		goto err_exit;

	res = interpret_flow_actions(dev, action, NULL, fd, error, &num_dest_port, &num_queues);

	if (res)
		goto err_exit;

	res = interpret_flow_elements(dev, elem, fd, error, forced_vlan_vid_local, &port_id,
		packet_data, packet_mask, &key_def);

	if (res)
		goto err_exit;

	pthread_mutex_lock(&dev->ndev->mtx);

	/* Translate group IDs */
	if (fd->jump_to_group != UINT32_MAX &&
		flow_group_translate_get(dev->ndev->group_handle, caller_id_local, dev->port,
		fd->jump_to_group, &fd->jump_to_group)) {
		NT_LOG(ERR, FILTER, "ERROR: Could not get group resource");
		flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
		goto err_exit;
	}

	if (attr_local.group > 0 &&
		flow_group_translate_get(dev->ndev->group_handle, caller_id_local, dev->port,
		attr_local.group, &attr_local.group)) {
		NT_LOG(ERR, FILTER, "ERROR: Could not get group resource");
		flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
		goto err_exit;
	}

	if (port_id == UINT32_MAX)
		port_id = dev->port_id;

	/* Create and flush filter to NIC */
	fh = create_flow_filter(dev, fd, &attr_local, forced_vlan_vid_local,
		caller_id_local, error, port_id, num_dest_port, num_queues, packet_data,
		packet_mask, &key_def);

	if (!fh)
		goto err_exit;

	NT_LOG(DBG, FILTER, "New FlOW: fh (flow handle) %p, fd (flow definition) %p", fh, fd);
	NT_LOG(DBG, FILTER, ">>>>> [Dev %p] Nic %i, Port %i: fh %p fd %p - implementation <<<<<",
		dev, dev->ndev->adapter_no, dev->port, fh, fd);

	pthread_mutex_unlock(&dev->ndev->mtx);

	return fh;

err_exit:

	if (fh)
		flow_destroy_locked_profile_inline(dev, fh, NULL);

	else
		free(fd);

	pthread_mutex_unlock(&dev->ndev->mtx);

	NT_LOG(ERR, FILTER, "ERR: %s", __func__);
	return NULL;
}

int flow_destroy_locked_profile_inline(struct flow_eth_dev *dev,
	struct flow_handle *fh,
	struct rte_flow_error *error)
{
	assert(dev);
	assert(fh);

	int err = 0;

	flow_nic_set_error(ERR_SUCCESS, error);

	/* take flow out of ndev list - may not have been put there yet */
	if (fh->type == FLOW_HANDLE_TYPE_FLM)
		nic_remove_flow_flm(dev->ndev, fh);

	else
		nic_remove_flow(dev->ndev, fh);

#ifdef FLOW_DEBUG
	dev->ndev->be.iface->set_debug_mode(dev->ndev->be.be_dev, FLOW_BACKEND_DEBUG_MODE_WRITE);
#endif

	NT_LOG(DBG, FILTER, "removing flow :%p", fh);
	if (fh->type == FLOW_HANDLE_TYPE_FLM) {
		hw_db_inline_deref_idxs(dev->ndev, dev->ndev->hw_db_handle,
			(struct hw_db_idx *)fh->flm_db_idxs,
			fh->flm_db_idx_counter);

		flm_flow_programming(fh, NT_FLM_OP_UNLEARN);

	} else {
		NT_LOG(DBG, FILTER, "removing flow :%p", fh);

		if (fh->fd->km.num_ftype_elem) {
			km_clear_data_match_entry(&fh->fd->km);

			const struct hw_db_inline_km_rcp_data *other_km_rcp_data =
				hw_db_inline_find_data(dev->ndev, dev->ndev->hw_db_handle,
				HW_DB_IDX_TYPE_KM_RCP,
				(struct hw_db_idx *)fh->flm_db_idxs,
				fh->flm_db_idx_counter);

			if (other_km_rcp_data != NULL &&
				flow_nic_deref_resource(dev->ndev, RES_KM_CATEGORY,
				(int)other_km_rcp_data->rcp) == 0) {
				hw_mod_km_rcp_set(&dev->ndev->be, HW_KM_RCP_PRESET_ALL,
					(int)other_km_rcp_data->rcp, 0, 0);
				hw_mod_km_rcp_flush(&dev->ndev->be, (int)other_km_rcp_data->rcp,
					1);
			}
		}

		hw_db_inline_deref_idxs(dev->ndev, dev->ndev->hw_db_handle,
			(struct hw_db_idx *)fh->db_idxs, fh->db_idx_counter);
		free(fh->fd);
	}

	if (err) {
		NT_LOG(ERR, FILTER, "FAILED removing flow: %p", fh);
		flow_nic_set_error(ERR_REMOVE_FLOW_FAILED, error);
	}

	free(fh);

#ifdef FLOW_DEBUG
	dev->ndev->be.iface->set_debug_mode(dev->ndev->be.be_dev, FLOW_BACKEND_DEBUG_MODE_NONE);
#endif

	return err;
}

int flow_destroy_profile_inline(struct flow_eth_dev *dev, struct flow_handle *flow,
	struct rte_flow_error *error)
{
	int err = 0;

	flow_nic_set_error(ERR_SUCCESS, error);

	if (flow) {
		/* Delete this flow */
		pthread_mutex_lock(&dev->ndev->mtx);
		err = flow_destroy_locked_profile_inline(dev, flow, error);
		pthread_mutex_unlock(&dev->ndev->mtx);
	}

	return err;
}

static __rte_always_inline bool all_bits_enabled(uint64_t hash_mask, uint64_t hash_bits)
{
	return (hash_mask & hash_bits) == hash_bits;
}

static __rte_always_inline void unset_bits(uint64_t *hash_mask, uint64_t hash_bits)
{
	*hash_mask &= ~hash_bits;
}

static __rte_always_inline void unset_bits_and_log(uint64_t *hash_mask, uint64_t hash_bits)
{
	char rss_buffer[4096];
	uint16_t rss_buffer_len = sizeof(rss_buffer);

	if (sprint_nt_rss_mask(rss_buffer, rss_buffer_len, " ", *hash_mask & hash_bits) == 0)
		NT_LOG(DBG, FILTER, "Configured RSS types:%s", rss_buffer);

	unset_bits(hash_mask, hash_bits);
}

static __rte_always_inline void unset_bits_if_all_enabled(uint64_t *hash_mask, uint64_t hash_bits)
{
	if (all_bits_enabled(*hash_mask, hash_bits))
		unset_bits(hash_mask, hash_bits);
}

int flow_nic_set_hasher_fields_inline(struct flow_nic_dev *ndev, int hsh_idx,
	struct nt_eth_rss_conf rss_conf)
{
	uint64_t fields = rss_conf.rss_hf;

	char rss_buffer[4096];
	uint16_t rss_buffer_len = sizeof(rss_buffer);

	if (sprint_nt_rss_mask(rss_buffer, rss_buffer_len, " ", fields) == 0)
		NT_LOG(DBG, FILTER, "Requested RSS types:%s", rss_buffer);

	/*
	 * configure all (Q)Words usable for hash calculation
	 * Hash can be calculated from 4 independent header parts:
	 *      | QW0           | Qw4           | W8| W9|
	 * word | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |
	 */
	struct hsh_words words[HSH_WORDS_SIZE] = {
		{ 0, 5, HW_HSH_RCP_QW0_PE, HW_HSH_RCP_QW0_OFS, 128, true },
		{ 4, 1, HW_HSH_RCP_QW4_PE, HW_HSH_RCP_QW4_OFS, 128, true },
		{ 8, 0, HW_HSH_RCP_W8_PE, HW_HSH_RCP_W8_OFS, 32, true },
		{
			9, 255, HW_HSH_RCP_W9_PE, HW_HSH_RCP_W9_OFS, 32,
			true
		},	/* not supported for Toeplitz */
	};

	int res = 0;
	res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_PRESET_ALL, hsh_idx, 0, 0);
	/* enable hashing */
	res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_LOAD_DIST_TYPE, hsh_idx, 0, 2);

	/* configure selected hash function and its key */
	bool toeplitz = false;

	switch (rss_conf.algorithm) {
	case RTE_ETH_HASH_FUNCTION_DEFAULT:
		/* Use default NTH10 hashing algorithm */
		res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_TOEPLITZ, hsh_idx, 0, 0);
		/* Use 1st 32-bits from rss_key to configure NTH10 SEED */
		res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_SEED, hsh_idx, 0,
			rss_conf.rss_key[0] << 24 | rss_conf.rss_key[1] << 16 |
			rss_conf.rss_key[2] << 8 | rss_conf.rss_key[3]);
		break;

	case RTE_ETH_HASH_FUNCTION_TOEPLITZ:
		toeplitz = true;
		res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_TOEPLITZ, hsh_idx, 0, 1);
		uint8_t empty_key = 0;

		/* Toeplitz key (always 40B) must be encoded from little to big endian */
		for (uint8_t i = 0; i <= (MAX_RSS_KEY_LEN - 8); i += 8) {
			res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_K, hsh_idx, i / 4,
				rss_conf.rss_key[i + 4] << 24 |
				rss_conf.rss_key[i + 5] << 16 |
				rss_conf.rss_key[i + 6] << 8 |
				rss_conf.rss_key[i + 7]);
			NT_LOG(DBG, FILTER,
				"hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_K, %d, %d, 0x%" PRIX32
				")",
				hsh_idx, i / 4,
				rss_conf.rss_key[i + 4] << 24 | rss_conf.rss_key[i + 5] << 16 |
				rss_conf.rss_key[i + 6] << 8 | rss_conf.rss_key[i + 7]);
			res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_K, hsh_idx, i / 4 + 1,
				rss_conf.rss_key[i] << 24 |
				rss_conf.rss_key[i + 1] << 16 |
				rss_conf.rss_key[i + 2] << 8 |
				rss_conf.rss_key[i + 3]);
			NT_LOG(DBG, FILTER,
				"hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_K, %d, %d, 0x%" PRIX32
				")",
				hsh_idx, i / 4 + 1,
				rss_conf.rss_key[i] << 24 | rss_conf.rss_key[i + 1] << 16 |
				rss_conf.rss_key[i + 2] << 8 | rss_conf.rss_key[i + 3]);
			empty_key |= rss_conf.rss_key[i] | rss_conf.rss_key[i + 1] |
				rss_conf.rss_key[i + 2] | rss_conf.rss_key[i + 3] |
				rss_conf.rss_key[i + 4] | rss_conf.rss_key[i + 5] |
				rss_conf.rss_key[i + 6] | rss_conf.rss_key[i + 7];
		}

		if (empty_key == 0) {
			NT_LOG(ERR, FILTER,
				"Toeplitz key must be configured. Key with all bytes set to zero is not allowed.");
			return -1;
		}

		words[HSH_WORDS_W9].free = false;
		NT_LOG(DBG, FILTER,
			"Toeplitz hashing is enabled thus W9 and P_MASK cannot be used.");
		break;

	default:
		NT_LOG(ERR, FILTER, "Unknown hashing function %d requested", rss_conf.algorithm);
		return -1;
	}

	/* indication that some IPv6 flag is present */
	bool ipv6 = fields & (NT_ETH_RSS_IPV6_MASK);
	/* store proto mask for later use at IP and L4 checksum handling */
	uint64_t l4_proto_mask = fields &
		(RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV4_UDP |
		RTE_ETH_RSS_NONFRAG_IPV4_SCTP | RTE_ETH_RSS_NONFRAG_IPV4_OTHER |
		RTE_ETH_RSS_NONFRAG_IPV6_TCP | RTE_ETH_RSS_NONFRAG_IPV6_UDP |
		RTE_ETH_RSS_NONFRAG_IPV6_SCTP | RTE_ETH_RSS_NONFRAG_IPV6_OTHER |
		RTE_ETH_RSS_IPV6_TCP_EX | RTE_ETH_RSS_IPV6_UDP_EX);

	/* outermost headers are used by default, so innermost bit takes precedence if detected */
	bool outer = (fields & RTE_ETH_RSS_LEVEL_INNERMOST) ? false : true;
	unset_bits(&fields, RTE_ETH_RSS_LEVEL_MASK);

	if (fields == 0) {
		NT_LOG(ERR, FILTER, "RSS hash configuration 0x%" PRIX64 " is not valid.",
			rss_conf.rss_hf);
		return -1;
	}

	/* indication that IPv4 `protocol` or IPv6 `next header` fields shall be part of the hash
	 */
	bool l4_proto_hash = false;

	/*
	 * check if SRC_ONLY & DST_ONLY are used simultaneously;
	 * According to DPDK, we shall behave like none of these bits is set
	 */
	unset_bits_if_all_enabled(&fields, RTE_ETH_RSS_L2_SRC_ONLY | RTE_ETH_RSS_L2_DST_ONLY);
	unset_bits_if_all_enabled(&fields, RTE_ETH_RSS_L3_SRC_ONLY | RTE_ETH_RSS_L3_DST_ONLY);
	unset_bits_if_all_enabled(&fields, RTE_ETH_RSS_L4_SRC_ONLY | RTE_ETH_RSS_L4_DST_ONLY);

	/* L2 */
	if (fields & (RTE_ETH_RSS_ETH | RTE_ETH_RSS_L2_SRC_ONLY | RTE_ETH_RSS_L2_DST_ONLY)) {
		if (outer) {
			if (fields & RTE_ETH_RSS_L2_SRC_ONLY) {
				NT_LOG(DBG, FILTER, "Set outer src MAC hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_L2, 6, 48, toeplitz);

			} else if (fields & RTE_ETH_RSS_L2_DST_ONLY) {
				NT_LOG(DBG, FILTER, "Set outer dst MAC hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_L2, 0, 48, toeplitz);

			} else {
				NT_LOG(DBG, FILTER, "Set outer src & dst MAC hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_L2, 0, 96, toeplitz);
			}

		} else if (fields & RTE_ETH_RSS_L2_SRC_ONLY) {
			NT_LOG(DBG, FILTER, "Set inner src MAC hasher.");
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_TUN_L2, 6,
				48, toeplitz);

		} else if (fields & RTE_ETH_RSS_L2_DST_ONLY) {
			NT_LOG(DBG, FILTER, "Set inner dst MAC hasher.");
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_TUN_L2, 0,
				48, toeplitz);

		} else {
			NT_LOG(DBG, FILTER, "Set inner src & dst MAC hasher.");
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_TUN_L2, 0,
				96, toeplitz);
		}

		unset_bits_and_log(&fields,
			RTE_ETH_RSS_ETH | RTE_ETH_RSS_L2_SRC_ONLY |
			RTE_ETH_RSS_L2_DST_ONLY);
	}

	/*
	 * VLAN support of multiple VLAN headers,
	 * where S-VLAN is the first and C-VLAN the last VLAN header
	 */
	if (fields & RTE_ETH_RSS_C_VLAN) {
		/*
		 * use MPLS protocol offset, which points just after ethertype with relative
		 * offset -6 (i.e. 2 bytes
		 * of ethertype & size + 4 bytes of VLAN header field) to access last vlan header
		 */
		if (outer) {
			NT_LOG(DBG, FILTER, "Set outer C-VLAN hasher.");
			/*
			 * use whole 32-bit 802.1a tag - backward compatible
			 * with VSWITCH implementation
			 */
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_MPLS, -6,
				32, toeplitz);

		} else {
			NT_LOG(DBG, FILTER, "Set inner C-VLAN hasher.");
			/*
			 * use whole 32-bit 802.1a tag - backward compatible
			 * with VSWITCH implementation
			 */
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_TUN_MPLS,
				-6, 32, toeplitz);
		}

		unset_bits_and_log(&fields, RTE_ETH_RSS_C_VLAN);
	}

	if (fields & RTE_ETH_RSS_S_VLAN) {
		if (outer) {
			NT_LOG(DBG, FILTER, "Set outer S-VLAN hasher.");
			/*
			 * use whole 32-bit 802.1a tag - backward compatible
			 * with VSWITCH implementation
			 */
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
				DYN_FIRST_VLAN, 0, 32, toeplitz);

		} else {
			NT_LOG(DBG, FILTER, "Set inner S-VLAN hasher.");
			/*
			 * use whole 32-bit 802.1a tag - backward compatible
			 * with VSWITCH implementation
			 */
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_TUN_VLAN,
				0, 32, toeplitz);
		}

		unset_bits_and_log(&fields, RTE_ETH_RSS_S_VLAN);
	}
	/* L2 payload */
	/* calculate hash of 128-bits of l2 payload; Use MPLS protocol offset to address the
	 * beginning of L2 payload even if MPLS header is not present
	 */
	if (fields & RTE_ETH_RSS_L2_PAYLOAD) {
		uint64_t outer_fields_enabled = 0;

		if (outer) {
			NT_LOG(DBG, FILTER, "Set outer L2 payload hasher.");
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_MPLS, 0,
				128, toeplitz);

		} else {
			NT_LOG(DBG, FILTER, "Set inner L2 payload hasher.");
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_TUN_MPLS,
				0, 128, toeplitz);
			outer_fields_enabled = fields & RTE_ETH_RSS_GTPU;
		}

		/*
		 * L2 PAYLOAD hashing overrides all L3 & L4 RSS flags.
		 * Thus we can clear all remaining (supported)
		 * RSS flags...
		 */
		unset_bits_and_log(&fields, NT_ETH_RSS_OFFLOAD_MASK);
		/*
		 * ...but in case of INNER L2 PAYLOAD we must process
		 * "always outer" GTPU field if enabled
		 */
		fields |= outer_fields_enabled;
	}

	/* L3 + L4 protocol number */
	if (fields & RTE_ETH_RSS_IPV4_CHKSUM) {
		/* only IPv4 checksum is supported by DPDK RTE_ETH_RSS_* types */
		if (ipv6) {
			NT_LOG(ERR, FILTER,
				"RSS: IPv4 checksum requested with IPv6 header hashing!");
			res = 1;

		} else if (outer) {
			NT_LOG(DBG, FILTER, "Set outer IPv4 checksum hasher.");
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_L3, 10,
				16, toeplitz);

		} else {
			NT_LOG(DBG, FILTER, "Set inner IPv4 checksum hasher.");
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_TUN_L3,
				10, 16, toeplitz);
		}

		/*
		 * L3 checksum is made from whole L3 header, i.e. no need to process other
		 * L3 hashing flags
		 */
		unset_bits_and_log(&fields, RTE_ETH_RSS_IPV4_CHKSUM | NT_ETH_RSS_IP_MASK);
	}

	if (fields & NT_ETH_RSS_IP_MASK) {
		if (ipv6) {
			if (outer) {
				if (fields & RTE_ETH_RSS_L3_SRC_ONLY) {
					NT_LOG(DBG, FILTER, "Set outer IPv6/IPv4 src hasher.");
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words,
						DYN_FINAL_IP_DST,
						-16, 128, toeplitz);

				} else if (fields & RTE_ETH_RSS_L3_DST_ONLY) {
					NT_LOG(DBG, FILTER, "Set outer IPv6/IPv4 dst hasher.");
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words,
						DYN_FINAL_IP_DST, 0,
						128, toeplitz);

				} else {
					NT_LOG(DBG, FILTER,
						"Set outer IPv6/IPv4 src & dst hasher.");
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words,
						DYN_FINAL_IP_DST,
						-16, 128, toeplitz);
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words,
						DYN_FINAL_IP_DST, 0,
						128, toeplitz);
				}

			} else if (fields & RTE_ETH_RSS_L3_SRC_ONLY) {
				NT_LOG(DBG, FILTER, "Set inner IPv6/IPv4 src hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_TUN_FINAL_IP_DST, -16,
					128, toeplitz);

			} else if (fields & RTE_ETH_RSS_L3_DST_ONLY) {
				NT_LOG(DBG, FILTER, "Set inner IPv6/IPv4 dst hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_TUN_FINAL_IP_DST, 0,
					128, toeplitz);

			} else {
				NT_LOG(DBG, FILTER, "Set inner IPv6/IPv4 src & dst hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_TUN_FINAL_IP_DST, -16,
					128, toeplitz);
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_TUN_FINAL_IP_DST, 0,
					128, toeplitz);
			}

			/* check if fragment ID shall be part of hash */
			if (fields & (RTE_ETH_RSS_FRAG_IPV4 | RTE_ETH_RSS_FRAG_IPV6)) {
				if (outer) {
					NT_LOG(DBG, FILTER,
						"Set outer IPv6/IPv4 fragment ID hasher.");
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words,
						DYN_ID_IPV4_6, 0,
						32, toeplitz);

				} else {
					NT_LOG(DBG, FILTER,
						"Set inner IPv6/IPv4 fragment ID hasher.");
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words,
						DYN_TUN_ID_IPV4_6,
						0, 32, toeplitz);
				}
			}

			res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_AUTO_IPV4_MASK, hsh_idx, 0,
				1);

		} else {
			/* IPv4 */
			if (outer) {
				if (fields & RTE_ETH_RSS_L3_SRC_ONLY) {
					NT_LOG(DBG, FILTER, "Set outer IPv4 src only hasher.");
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words, DYN_L3, 12,
						32, toeplitz);

				} else if (fields & RTE_ETH_RSS_L3_DST_ONLY) {
					NT_LOG(DBG, FILTER, "Set outer IPv4 dst only hasher.");
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words, DYN_L3, 16,
						32, toeplitz);

				} else {
					NT_LOG(DBG, FILTER, "Set outer IPv4 src & dst hasher.");
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words, DYN_L3, 12,
						64, toeplitz);
				}

			} else if (fields & RTE_ETH_RSS_L3_SRC_ONLY) {
				NT_LOG(DBG, FILTER, "Set inner IPv4 src only hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_TUN_L3, 12, 32,
					toeplitz);

			} else if (fields & RTE_ETH_RSS_L3_DST_ONLY) {
				NT_LOG(DBG, FILTER, "Set inner IPv4 dst only hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_TUN_L3, 16, 32,
					toeplitz);

			} else {
				NT_LOG(DBG, FILTER, "Set inner IPv4 src & dst hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_TUN_L3, 12, 64,
					toeplitz);
			}

			/* check if fragment ID shall be part of hash */
			if (fields & RTE_ETH_RSS_FRAG_IPV4) {
				if (outer) {
					NT_LOG(DBG, FILTER,
						"Set outer IPv4 fragment ID hasher.");
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words,
						DYN_ID_IPV4_6, 0,
						16, toeplitz);

				} else {
					NT_LOG(DBG, FILTER,
						"Set inner IPv4 fragment ID hasher.");
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words,
						DYN_TUN_ID_IPV4_6,
						0, 16, toeplitz);
				}
			}
		}

		/* check if L4 protocol type shall be part of hash */
		if (l4_proto_mask)
			l4_proto_hash = true;

		unset_bits_and_log(&fields, NT_ETH_RSS_IP_MASK);
	}

	/* L4 */
	if (fields & (RTE_ETH_RSS_PORT | RTE_ETH_RSS_L4_SRC_ONLY | RTE_ETH_RSS_L4_DST_ONLY)) {
		if (outer) {
			if (fields & RTE_ETH_RSS_L4_SRC_ONLY) {
				NT_LOG(DBG, FILTER, "Set outer L4 src hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_L4, 0, 16, toeplitz);

			} else if (fields & RTE_ETH_RSS_L4_DST_ONLY) {
				NT_LOG(DBG, FILTER, "Set outer L4 dst hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_L4, 2, 16, toeplitz);

			} else {
				NT_LOG(DBG, FILTER, "Set outer L4 src & dst hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_L4, 0, 32, toeplitz);
			}

		} else if (fields & RTE_ETH_RSS_L4_SRC_ONLY) {
			NT_LOG(DBG, FILTER, "Set inner L4 src hasher.");
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_TUN_L4, 0,
				16, toeplitz);

		} else if (fields & RTE_ETH_RSS_L4_DST_ONLY) {
			NT_LOG(DBG, FILTER, "Set inner L4 dst hasher.");
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_TUN_L4, 2,
				16, toeplitz);

		} else {
			NT_LOG(DBG, FILTER, "Set inner L4 src & dst hasher.");
			res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_TUN_L4, 0,
				32, toeplitz);
		}

		l4_proto_hash = true;
		unset_bits_and_log(&fields,
			RTE_ETH_RSS_PORT | RTE_ETH_RSS_L4_SRC_ONLY |
			RTE_ETH_RSS_L4_DST_ONLY);
	}

	/* IPv4 protocol / IPv6 next header fields */
	if (l4_proto_hash) {
		/* NOTE: HW_HSH_RCP_P_MASK is not supported for Toeplitz and thus one of SW0, SW4
		 * or W8 must be used to hash on `protocol` field of IPv4 or `next header` field of
		 * IPv6 header.
		 */
		if (outer) {
			NT_LOG(DBG, FILTER, "Set outer L4 protocol type / next header hasher.");

			if (toeplitz) {
				if (ipv6) {
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words, DYN_L3, 6, 8,
						toeplitz);

				} else {
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words, DYN_L3, 9, 8,
						toeplitz);
				}

			} else {
				res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_P_MASK, hsh_idx, 0,
					1);
				res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_TNL_P, hsh_idx, 0,
					0);
			}

		} else {
			NT_LOG(DBG, FILTER, "Set inner L4 protocol type / next header hasher.");

			if (toeplitz) {
				if (ipv6) {
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words, DYN_TUN_L3,
						6, 8, toeplitz);

				} else {
					res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx,
						words, DYN_TUN_L3,
						9, 8, toeplitz);
				}

			} else {
				res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_P_MASK, hsh_idx, 0,
					1);
				res |= hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_TNL_P, hsh_idx, 0,
					1);
			}
		}

		l4_proto_hash = false;
	}

	/*
	 * GTPU - for UPF use cases we always use TEID from outermost GTPU header
	 * even if other headers are innermost
	 */
	if (fields & RTE_ETH_RSS_GTPU) {
		NT_LOG(DBG, FILTER, "Set outer GTPU TEID hasher.");
		res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words, DYN_L4_PAYLOAD, 4, 32,
			toeplitz);
		unset_bits_and_log(&fields, RTE_ETH_RSS_GTPU);
	}

	/* Checksums */
	/* only UDP, TCP and SCTP checksums are supported */
	if (fields & RTE_ETH_RSS_L4_CHKSUM) {
		switch (l4_proto_mask) {
		case RTE_ETH_RSS_NONFRAG_IPV4_UDP:
		case RTE_ETH_RSS_NONFRAG_IPV6_UDP:
		case RTE_ETH_RSS_IPV6_UDP_EX:
		case RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_NONFRAG_IPV6_UDP:
		case RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_IPV6_UDP_EX:
		case RTE_ETH_RSS_NONFRAG_IPV6_UDP | RTE_ETH_RSS_IPV6_UDP_EX:
		case RTE_ETH_RSS_UDP_COMBINED:
			if (outer) {
				NT_LOG(DBG, FILTER, "Set outer UDP checksum hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_L4, 6, 16, toeplitz);

			} else {
				NT_LOG(DBG, FILTER, "Set inner UDP checksum hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_TUN_L4, 6, 16,
					toeplitz);
			}

			unset_bits_and_log(&fields, RTE_ETH_RSS_L4_CHKSUM | l4_proto_mask);
			break;

		case RTE_ETH_RSS_NONFRAG_IPV4_TCP:
		case RTE_ETH_RSS_NONFRAG_IPV6_TCP:
		case RTE_ETH_RSS_IPV6_TCP_EX:
		case RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV6_TCP:
		case RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_IPV6_TCP_EX:
		case RTE_ETH_RSS_NONFRAG_IPV6_TCP | RTE_ETH_RSS_IPV6_TCP_EX:
		case RTE_ETH_RSS_TCP_COMBINED:
			if (outer) {
				NT_LOG(DBG, FILTER, "Set outer TCP checksum hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_L4, 16, 16, toeplitz);

			} else {
				NT_LOG(DBG, FILTER, "Set inner TCP checksum hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_TUN_L4, 16, 16,
					toeplitz);
			}

			unset_bits_and_log(&fields, RTE_ETH_RSS_L4_CHKSUM | l4_proto_mask);
			break;

		case RTE_ETH_RSS_NONFRAG_IPV4_SCTP:
		case RTE_ETH_RSS_NONFRAG_IPV6_SCTP:
		case RTE_ETH_RSS_NONFRAG_IPV4_SCTP | RTE_ETH_RSS_NONFRAG_IPV6_SCTP:
			if (outer) {
				NT_LOG(DBG, FILTER, "Set outer SCTP checksum hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_L4, 8, 32, toeplitz);

			} else {
				NT_LOG(DBG, FILTER, "Set inner SCTP checksum hasher.");
				res |= flow_nic_set_hasher_part_inline(ndev, hsh_idx, words,
					DYN_TUN_L4, 8, 32,
					toeplitz);
			}

			unset_bits_and_log(&fields, RTE_ETH_RSS_L4_CHKSUM | l4_proto_mask);
			break;

		case RTE_ETH_RSS_NONFRAG_IPV4_OTHER:
		case RTE_ETH_RSS_NONFRAG_IPV6_OTHER:

		/* none or unsupported protocol was chosen */
		case 0:
			NT_LOG(ERR, FILTER,
				"L4 checksum hashing is supported only for UDP, TCP and SCTP protocols");
			res = -1;
			break;

		/* multiple L4 protocols were selected */
		default:
			NT_LOG(ERR, FILTER,
				"L4 checksum hashing can be enabled just for one of UDP, TCP or SCTP protocols");
			res = -1;
			break;
		}
	}

	if (fields || res != 0) {
		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_PRESET_ALL, hsh_idx, 0, 0);

		if (sprint_nt_rss_mask(rss_buffer, rss_buffer_len, " ", rss_conf.rss_hf) == 0) {
			NT_LOG(ERR, FILTER,
				"RSS configuration%s is not supported for hash func %s.",
				rss_buffer,
				(enum rte_eth_hash_function)toeplitz ? "Toeplitz" : "NTH10");

		} else {
			NT_LOG(ERR, FILTER,
				"RSS configuration 0x%" PRIX64
				" is not supported for hash func %s.",
				rss_conf.rss_hf,
				(enum rte_eth_hash_function)toeplitz ? "Toeplitz" : "NTH10");
		}

		return -1;
	}

	return res;
}


static const struct profile_inline_ops ops = {
	/*
	 * Management
	 */
	.done_flow_management_of_ndev_profile_inline = done_flow_management_of_ndev_profile_inline,
	.initialize_flow_management_of_ndev_profile_inline =
		initialize_flow_management_of_ndev_profile_inline,
	/*
	 * Flow functionality
	 */
	.flow_destroy_locked_profile_inline = flow_destroy_locked_profile_inline,
	.flow_create_profile_inline = flow_create_profile_inline,
	.flow_destroy_profile_inline = flow_destroy_profile_inline,
	.flow_nic_set_hasher_fields_inline = flow_nic_set_hasher_fields_inline,
};

void profile_inline_init(void)
{
	register_profile_inline_ops(&ops);
}