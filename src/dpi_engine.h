//
// Created by fireflyc on 2016/12/29.
//

#ifndef DPI_SERVER_DPI_ENGINE_H
#define DPI_SERVER_DPI_ENGINE_H

#include <stdlib.h>
#include <ndpi_api.h>
#include "config.h"

#define MAX_IDLE_TIME           30000
#define NUM_ROOTS                 512

typedef struct _dpi_struct {
    ndpi_detection_module_struct_t *ndpi_struct;
    uint64_t dpi_flow_count;
    uint64_t last_time;//最后一次抓取数据时间
    void *dpi_flows_root[NUM_ROOTS];
    uint64_t num_idle_flows;
    void *idle_flows[NUM_ROOTS];
    uint64_t idle_scan_idx;
} dpi_struct_t;

typedef struct _dpi_flow {
    //每次通讯都会有源、目标IP和端口，下面的四个成员会把它们之后保存
    uint32_t lower_ip;//小IP
    uint32_t upper_ip;//大IP
    uint16_t lower_port;//小端口
    uint16_t upper_port;//大端口

    //vlanid
    uint16_t vlan_id;

    char lower_name[32], upper_name[32];//字符串形式的IP地址

    uint8_t protocol; //IPPROTO_TCP IPPROTO_TCP

    struct ndpi_flow_struct *ndpi_flow;//单独释放

    uint64_t bytes;
    uint32_t packets;

    uint64_t last_seen;//最后更新时间

    //识别出来的协议
    uint32_t detected_protocol;

    u_int32_t idx;//dpi_flows_root中的位置
} dpi_flow_t;

void dpi_free(dpi_struct_t *dpi_struct);

dpi_struct_t *init_dpi(dpi_server_config_t config, char *errbuf);

int dpi_packet_processing(dpi_struct_t *dpi_struct,
                          struct ndpi_iphdr *iph4, struct ndpi_ip6_hdr *iph6, struct timeval time,
                          uint16_t vlan_id, uint16_t ipsize, uint16_t rawsize, char *errbuf);

#endif //DPI_SERVER_DPI_ENGINE_H
