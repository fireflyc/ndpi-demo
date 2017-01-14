//
// Created by fireflyc on 2016/12/22.
//
#include <stdlib.h>
#include <libconfig.h>
#include <memory.h>
#include <errno.h>
#include "config.h"

int init_config_from_file(dpi_server_config_t *config, const char *config_path, char *errbuf) {
    config_t cfg;
    config_init(&cfg);
    if (!config_read_file(&cfg, config_path)) {
        snprintf(errbuf, BUFSIZ, "%s:%d - %s", config_error_file(&cfg), config_error_line(&cfg),
                 config_error_text(&cfg));
        goto bad;
    }
    config_lookup_string(&cfg, "filter_exp", (const char **) &config->filter_exp);
    if (!config_lookup_string(&cfg, "sniff_dev", (const char **) &config->sniff_dev)) {
        snprintf(errbuf, BUFSIZ, "No '%s' setting in configuration file", "sniff_dev");
        goto bad;
    }
    config_lookup_string(&cfg, "proto_file_path", (const char **) &config->proto_file_path);
    if (config->proto_file_path != NULL) {
        //测试文件是否存在
        if (fopen(config->proto_file_path, "r") == NULL) {
            snprintf(errbuf, BUFSIZ, "Unable to open file %s [%s]", config->proto_file_path, strerror(errno));
            goto bad;
        }
    }
    return TRUE;

    bad:
    config_destroy(&cfg);
    return FALSE;
}