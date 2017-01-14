#include <getopt.h>
#include <ndpi_api.h>
#include "main.h"
#include "context.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

static zlog_category_t *packet_log_category;

void pcap_packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    dpi_server_context_t *server_context = (dpi_server_context_t *) args;
    if (packet_log_category == NULL) {
        packet_log_category = zlog_get_category("packet");
    }

    struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *) packet;
    uint16_t ip_offset = sizeof(struct ndpi_ethhdr);
    uint16_t type = ntohs(ethernet->h_proto);
    uint16_t vlan_id = 1;
    //标准以太网,IEEE 802.1Q,ipv6
    if (type != 0x8100 && type != 0x0800 && type != 0x86DD) {
        goto bad;
    }
    if (type == 0x8100 /* VLAN */) {
        struct ndpi_80211q *vlan_priority_c_vid = (struct ndpi_80211q *) (packet + ip_offset);
        vlan_id = ntohs(vlan_priority_c_vid->vlanId);
        type = ntohs(vlan_priority_c_vid->protoType);
        ip_offset += sizeof(struct ndpi_80211q);
    }
    struct ndpi_iphdr *iph = (struct ndpi_iphdr *) &packet[ip_offset];
    if (type == ETH_P_IP) {
        //空IP数据包？
        if (header->caplen <= ip_offset) {
            log_warn(packet_log_category, "ip packet is empty,skip");
            goto bad;
        }
        //捕获到了不完整的IP数据包
        if (header->caplen < header->len) {
            log_warn(packet_log_category, "incomplete data packet caplen=%d len=%d", header->caplen, header->len);
            //hzlog_info(packet_log_category, packet, header->len);
            goto bad;
        }
    }
    char errbuf[BUFSIZ];
    if (iph->version == 4) {
        dpi_packet_processing(server_context->dpi_struct, iph, NULL, header->ts, vlan_id, header->len - ip_offset,
                              header->len, errbuf);
    } else if (iph->version == 6) {
        struct ndpi_ip6_hdr *iph6 = (struct ndpi_ip6_hdr *) &packet[ip_offset];
        dpi_packet_processing(server_context->dpi_struct, iph, iph6, header->ts, vlan_id, header->len - ip_offset,
                              header->len, errbuf);
    } else {
        //未知的IP协议版本
        log_warn(packet_log_category, "unknow ip version %d len=%d", iph->version, header->len);
        //hzlog_info(packet_log_category, packet + ip_offset, header->len);
        goto bad;
    }

    bad:
    return;
}

zlog_category_t *init_logger(const char *logging_path, char *errbuf) {
    int rc = zlog_init(logging_path);
    if (rc) {
        snprintf(errbuf, BUFSIZ, "init logger failed");
        return NULL;
    }
    zlog_category_t *category = zlog_get_category("main");
    if (!category) {
        snprintf(errbuf, BUFSIZ, "Get Logger category failed");
        zlog_fini();
        return NULL;
    }
    return category;
}

pcap_t *init_pcap(dpi_server_config_t config, char *errbuf) {
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    if (pcap_lookupnet(config.sniff_dev, &netp, &maskp, errbuf) == -1) {
        snprintf(errbuf, BUFSIZ, "lookup %s failed", config.sniff_dev);
        return NULL;
    }
    pcap_t *pcap = pcap_open_live(config.sniff_dev, 262144, 1, 1, errbuf);
    if (pcap == NULL) {
        return NULL;
    }
    if (config.filter_exp != NULL) {
        struct bpf_program fp;
        if (pcap_compile(pcap, &fp, config.filter_exp, 1, netp) == -1) {
            snprintf(errbuf, BUFSIZ, "Compile filter expression failed %s cause: %s", config.filter_exp,
                     pcap_geterr(pcap));
            pcap_close(pcap);
            return NULL;
        }
        if (pcap_setfilter(pcap, &fp) == -1) {
            snprintf(errbuf, BUFSIZ, "Install filter failed %s", pcap_geterr(pcap));
            pcap_close(pcap);
            return NULL;
        }
    }
    return pcap;
}

void print_usage() {
    printf("usage ndpi-demo -l<logging file path> -c<config file path>\n");
}

int main(int argc, char **argv) {
    char *config_path = NULL;
    char *logging_path = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "l:c:")) != -1) {
        switch (opt) {
            case 'l':
                logging_path = optarg;
                break;
            case 'c':
                config_path = optarg;
                break;
            default:
                break;
        }
    }
    if ((logging_path == NULL || config_path == NULL)) {
        print_usage();
        return EXIT_FAILURE;
    }
    FILE *fptr;
    if ((fptr = fopen(logging_path, "r")) == NULL) {
        CORE_LOG("open logging file %s failed\n", logging_path);
        return EXIT_FAILURE;
    }
    fclose(fptr);
    if ((fptr = fopen(config_path, "r")) == NULL) {
        CORE_LOG("open config file %s failed\n", config_path);
        return EXIT_FAILURE;
    }
    fclose(fptr);

    char errbuf[BUFSIZ];
    //初始化日志
    zlog_category_t *root_category = init_logger(logging_path, errbuf);
    //初始化配置文件
    dpi_server_config_t config;
    memset(&config, 0, sizeof(dpi_server_config_t));

    if (!init_config_from_file(&config, config_path, errbuf)) {
        log_error(root_category, "init config failed %s", errbuf);
        return EXIT_FAILURE;
    }
    //初始化server_context
    dpi_server_context_t server_context;

    memset(&server_context, 0, sizeof(server_context));
    server_context.dpi_struct = init_dpi(config, errbuf);
    if (server_context.dpi_struct == NULL) {
        log_error(root_category, "init dpi engine failed %s", errbuf);
        return EXIT_FAILURE;
    }
    server_context.pcap = init_pcap(config, errbuf);
    if (server_context.pcap == NULL) {
        log_error(root_category, "init pcap failed %s", errbuf);
        return EXIT_FAILURE;
    }
    log_info(root_category, "Start Success in %s use exp %s", config.sniff_dev, config.filter_exp);
    pcap_loop(server_context.pcap, -1, pcap_packet_callback, (u_char *) &server_context);

    //释放资源(其实执行不到)
    pcap_close(server_context.pcap);
    return 0;
}
