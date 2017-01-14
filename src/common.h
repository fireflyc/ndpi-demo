//
// Created by fireflyc on 2016/12/22.
//

#ifndef DPI_SERVER_COMMON_H
#define DPI_SERVER_COMMON_H

#include <stdio.h>
#include <zlog.h>

#define TRUE 1==1
#define FALSE 1==0
#define CORE_LOG(...) fprintf(stdout, __VA_ARGS__)

#define log_debug(...)  zlog_debug(__VA_ARGS__)
#define log_error(...) zlog_error(__VA_ARGS__)
#define log_info(...) zlog_info(__VA_ARGS__)
#define log_warn(...) zlog_warn(__VA_ARGS__)

#endif //DPI_SERVER_COMMON_H
