//
// Created by fireflyc on 2016/12/22.
//

#ifndef DPI_SERVER_CONTEXT_H
#define DPI_SERVER_CONTEXT_H

#include <ndpi_api.h>
#include <zlog.h>
#include <pcap.h>
#include "dpi_engine.h"

struct _dpi_struct;

typedef struct dpi_server_context {
    struct _dpi_struct *dpi_struct;
    pcap_t *pcap;
} dpi_server_context_t;
#endif //DPI_SERVER_CONTEXT_H
