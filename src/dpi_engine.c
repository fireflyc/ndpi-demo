//
// Created by fireflyc on 2016/12/29.
//
#include "dpi_engine.h"

#define DPI_LOG_TAG "ndpi"

/**
 * glibc分配内存或许可以用memory pool
 * **/
static void *malloc_wrapper(unsigned long size) {
    return malloc(size);
}

static void free_wrapper(void *freeable) {
    free(freeable);
}

static zlog_category_t *ndpi_log_cate = NULL;

static void debug_log(u_int32_t protocol, void *id_struct, ndpi_log_level_t log_level, const char *format, ...) {
    va_list va_ap;
    if (ndpi_log_cate == NULL) {
        ndpi_log_cate = zlog_get_category(DPI_LOG_TAG);
    }
    if (log_level == NDPI_LOG_ERROR) {
        va_start (va_ap, format);
        log_error(ndpi_log_cate, format, va_ap);
        va_end(va_ap);
    }
    if (log_level == NDPI_LOG_TRACE) {
        va_start (va_ap, format);
        log_info(ndpi_log_cate, format, va_ap);
        va_end(va_ap);
    }
    if (log_level == NDPI_LOG_DEBUG) {
        va_start (va_ap, format);
        log_debug(ndpi_log_cate, format, va_ap);
        va_end(va_ap);
    }
}

void dpi_free(dpi_struct_t *dpi_struct) {
    if (dpi_struct->ndpi_struct != NULL) {
        ndpi_free(dpi_struct->ndpi_struct);
        dpi_struct->ndpi_struct = NULL;
    }
    free(dpi_struct);
}

dpi_struct_t *init_dpi(dpi_server_config_t config, char *errbuf) {
    dpi_struct_t *dpi_struct = (dpi_struct_t *) malloc(sizeof(dpi_struct_t));
    if (dpi_struct == NULL) {
        snprintf(errbuf, BUFSIZ, "not enough memory");
        return NULL;
    }
    dpi_struct->ndpi_struct = ndpi_init_detection_module(1000,
                                                         malloc_wrapper, free_wrapper,
                                                         debug_log);
    if (dpi_struct->ndpi_struct == NULL) {
        snprintf(errbuf, BUFSIZ, "init ndpi error");
        dpi_free(dpi_struct);
        return NULL;
    }
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    //去掉不需要的协议
    NDPI_BITMASK_DEL(all, NDPI_PROTOCOL_FTP_DATA);
    NDPI_BITMASK_DEL(all, NDPI_PROTOCOL_FTP_CONTROL);
    ndpi_set_protocol_detection_bitmask2(dpi_struct->ndpi_struct, &all);
    if (config.proto_file_path != NULL) {
        ndpi_load_protocols_file(dpi_struct->ndpi_struct, config.proto_file_path);
    }
    return dpi_struct;
}


void free_ndpi_flow(dpi_struct_t *dpi_struct, dpi_flow_t *flow) {
    if (flow->ndpi_flow) {
        ndpi_free_flow(flow->ndpi_flow);
        dpi_struct->dpi_flow_count--;
        flow->ndpi_flow = NULL;
    }
}

static int node_cmp(const void *a, const void *b) {
    dpi_flow_t *fa = (dpi_flow_t *) a;
    dpi_flow_t *fb = (dpi_flow_t *) b;

    if (fa->vlan_id < fb->vlan_id) return (-1); else { if (fa->vlan_id > fb->vlan_id) return (1); }
    if (fa->lower_ip < fb->lower_ip) return (-1); else { if (fa->lower_ip > fb->lower_ip) return (1); }
    if (fa->lower_port < fb->lower_port) return (-1); else { if (fa->lower_port > fb->lower_port) return (1); }
    if (fa->upper_ip < fb->upper_ip) return (-1); else { if (fa->upper_ip > fb->upper_ip) return (1); }
    if (fa->upper_port < fb->upper_port) return (-1); else { if (fa->upper_port > fb->upper_port) return (1); }
    if (fa->protocol < fb->protocol) return (-1); else { if (fa->protocol > fb->protocol) return (1); }

    return (0);
}

int fill_ip_and_port(const struct ndpi_iphdr *iph, const struct ndpi_ip6_hdr *iph6, const uint8_t version,
                     const uint16_t ipsize, dpi_flow_t *flow, char *errbuf) {
    uint16_t l4_packet_len = ntohs(iph->tot_len) - (iph->ihl * 4);
    if (iph6 != NULL) {
        l4_packet_len = ntohs(iph6->ip6_ctlun.ip6_un1.ip6_un1_plen);
    }

    uint32_t l4_offset;
    u_int32_t lower_ip;
    u_int32_t upper_ip;
    u_int16_t lower_port;
    u_int16_t upper_port;
    u_int8_t *l3;
    //确定应用数据包的位置
    if (version == 4) {
        if (ipsize < 20)
            return FALSE;

        if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
            || (iph->frag_off & htons(0x1FFF)) != 0)
            return FALSE;

        l4_offset = iph->ihl * 4;
        l3 = (u_int8_t *) iph;
    } else {
        l4_offset = sizeof(struct ndpi_ip6_hdr);
        l3 = (u_int8_t *) iph6;
    }

    //记录IP地址(比较大小)
    if (iph->saddr < iph->daddr) {
        lower_ip = iph->saddr;
        upper_ip = iph->daddr;
    } else {
        lower_ip = iph->daddr;
        upper_ip = iph->saddr;
    }

    //记录端口(比较大小)
    if (iph->protocol == IPPROTO_TCP && l4_packet_len >= 20) {
        // tcp
        struct ndpi_tcphdr *tcph = (struct ndpi_tcphdr *) (l3 + l4_offset);
        if (iph->saddr < iph->daddr) {
            lower_port = tcph->source;
            upper_port = tcph->dest;
        } else {
            lower_port = tcph->dest;
            upper_port = tcph->source;

            if (iph->saddr == iph->daddr) {
                if (lower_port > upper_port) {
                    u_int16_t p = lower_port;

                    lower_port = upper_port;
                    upper_port = p;
                }
            }
        }
    } else if (iph->protocol == IPPROTO_UDP && l4_packet_len >= 8) {
        // udp
        struct ndpi_udphdr *udph = (struct ndpi_udphdr *) (l3 + l4_offset);
        if (iph->saddr < iph->daddr) {
            lower_port = udph->source;
            upper_port = udph->dest;
        } else {
            lower_port = udph->dest;
            upper_port = udph->source;
        }
    } else {
        snprintf(errbuf, BUFSIZ, "unknow ip type %d", iph->protocol);
        return FALSE;
    }

    flow->lower_ip = lower_ip, flow->upper_ip = upper_ip;
    flow->lower_port = lower_port, flow->upper_port = upper_port;
    return TRUE;
}

dpi_flow_t *get_ndpi_flow(dpi_struct_t *dpi_struct, const struct ndpi_iphdr *iph,
                          const struct ndpi_ip6_hdr *iph6, const uint8_t version, const uint16_t vlan_id,
                          const uint16_t ipsize, char *errbuf) {

    dpi_flow_t flow;
    flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
    if (!fill_ip_and_port(iph, iph6, version, ipsize, &flow, errbuf)) {
        return NULL;
    }


    u_int32_t idx =
            (vlan_id + flow.lower_ip + flow.upper_ip + iph->protocol + flow.lower_port +
             flow.upper_port) % NUM_ROOTS;
    void *ret = ndpi_tfind(&flow, &dpi_struct->dpi_flows_root[idx], node_cmp);

    if (ret == NULL) {
        dpi_flow_t *newflow = (dpi_flow_t *) malloc_wrapper(sizeof(dpi_flow_t));

        if (newflow == NULL) {
            snprintf(errbuf, BUFSIZ, "not enough memory");
            return (NULL);
        }

        memset(newflow, 0, sizeof(dpi_flow_t));
        newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
        newflow->lower_ip = flow.lower_ip, newflow->upper_ip = flow.upper_ip;
        newflow->lower_port = flow.lower_port, newflow->upper_port = flow.upper_port;
        newflow->idx = idx;
        if (version == 4) {
            inet_ntop(AF_INET, &flow.lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
            inet_ntop(AF_INET, &flow.upper_ip, newflow->upper_name, sizeof(newflow->upper_name));
        } else {
            inet_ntop(AF_INET6, &iph6->ip6_src, newflow->lower_name, sizeof(newflow->lower_name));
            inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->upper_name, sizeof(newflow->upper_name));
        }

        size_t size_flow_struct = sizeof(struct ndpi_flow_struct);
        if ((newflow->ndpi_flow = malloc_wrapper(size_flow_struct)) == NULL) {
            snprintf(errbuf, BUFSIZ, "not enough memory");
            return (NULL);
        } else {
            memset(newflow->ndpi_flow, 0, size_flow_struct);
        }

        //插入到dpi_flows_root
        ndpi_tsearch(newflow, &dpi_struct->dpi_flows_root[idx], node_cmp);
        dpi_struct->dpi_flow_count++;
        return (newflow);
    } else {
        dpi_flow_t *exist = *(dpi_flow_t **) ret;
        return exist;
    }
}

void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    dpi_flow_t *flow = *(dpi_flow_t **) node;
    dpi_struct_t *dpi_struct = (dpi_struct_t *) user_data;

    if ((which == ndpi_preorder) || (which == ndpi_leaf)) {
        if (flow->last_seen + MAX_IDLE_TIME < dpi_struct->last_time) {
            free_ndpi_flow(dpi_struct, flow);
            //一次找到所有
            dpi_struct->idle_flows[dpi_struct->num_idle_flows++] = flow;
        }
    }
}


int dpi_packet_processing(dpi_struct_t *dpi_struct,
                          struct ndpi_iphdr *iph4, struct ndpi_ip6_hdr *iph6, struct timeval ts,
                          uint16_t vlan_id, uint16_t ipsize, uint16_t rawsize, char *errbuf) {
    if (ndpi_log_cate == NULL) {
        ndpi_log_cate = zlog_get_category(DPI_LOG_TAG);
    }
    dpi_flow_t *flow = NULL;
    if (iph4 != NULL) {
        flow = get_ndpi_flow(dpi_struct, iph4, NULL, 4, vlan_id, ipsize, errbuf);
    } else if (iph6 != NULL) {
        struct ndpi_iphdr iph;

        memset(&iph, 0, sizeof(iph));
        iph.version = 4;
        iph.saddr = iph6->ip6_src.__u6_addr.__u6_addr32[2] + iph6->ip6_src.__u6_addr.__u6_addr32[3];
        iph.daddr = iph6->ip6_dst.__u6_addr.__u6_addr32[2] + iph6->ip6_dst.__u6_addr.__u6_addr32[3];
        iph.protocol = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

        if (iph.protocol == 0x3C /* IPv6 destination option */) {
            u_int8_t *options = (u_int8_t *) iph6 + sizeof(const struct ndpi_ip6_hdr);

            iph.protocol = options[0];
        }
        flow = get_ndpi_flow(dpi_struct, &iph, iph6, 6, vlan_id, ipsize, errbuf);
    }
    if (flow == NULL) {
        return FALSE;
    }
    uint64_t now = ((uint64_t) ts.tv_sec) * 1000 + ts.tv_usec;
    log_info(ndpi_log_cate, "time=%l", now);
    flow->packets++;
    flow->bytes += rawsize;
    flow->last_seen = now;
    dpi_struct->last_time = now;
    //不需要更新协议类型所以最后两个参数为NULL
    flow->detected_protocol = (const u_int32_t) ndpi_detection_process_packet(dpi_struct->ndpi_struct, flow->ndpi_flow,
                                                                              iph4 ? (uint8_t *) iph4
                                                                                   : (uint8_t *) iph6,
                                                                              ipsize, now, NULL, NULL);


    //释放分两步,首先释放flow->ndpi_flow(ndpi_twalk的时候完成)，之后从tree里把flow移除
    if ((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)) {
        //hzlog_info(ndpi_log_cate, iph4, ipsize);
        log_info(ndpi_log_cate, "%s", ndpi_get_proto_by_id(dpi_struct->ndpi_struct, flow->detected_protocol));
        //识别出协议
        free_ndpi_flow(dpi_struct, flow);
        ndpi_tdelete(flow, &dpi_struct->dpi_flows_root[flow->idx], node_cmp);
    }
    //清理长时间不用的packet
    ndpi_twalk(dpi_struct->dpi_flows_root[dpi_struct->idle_scan_idx],
               node_idle_scan_walker, dpi_struct);
    if (dpi_struct->num_idle_flows > 0) {
        log_info(ndpi_log_cate, "idle_scan_idx=%d num_idle_flows=%d", dpi_struct->idle_scan_idx,
                 dpi_struct->num_idle_flows);
    }
    while (dpi_struct->num_idle_flows > 0) {
        //释放的时候调用的是free_wrapper
        ndpi_tdelete(dpi_struct->idle_flows[--dpi_struct->num_idle_flows],
                     &dpi_struct->dpi_flows_root[dpi_struct->idle_scan_idx], node_cmp);
    }
    if (++dpi_struct->idle_scan_idx == NUM_ROOTS) {
        dpi_struct->idle_scan_idx = 0;
    }
    return TRUE;
}