//
// Created by fireflyc on 2016/12/22.
//

#ifndef DPI_SERVER_CONFIG_H
#define DPI_SERVER_CONFIG_H

#include "common.h"

typedef struct dpi_server_config {
    char *sniff_dev;
    char *filter_exp;
    char *proto_file_path;
} dpi_server_config_t;

int init_config_from_file(dpi_server_config_t *config, const char *config_path, char *errbuf);

#endif //DPI_SERVER_CONFIG_H
