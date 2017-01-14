/*
 * This file is part of the zlog Library.
 *
 * Copyright (C) 2011 by Hardy Simpson <HardySimpson1984@gmail.com>
 *
 * Licensed under the LGPL v2.1, see the file COPYING in base directory.
 */

#ifndef __zc_defs_h
#define __zc_defs_h

#include "zc_profile.h"
#include "zc_arraylist.h"
#include "zc_hashtable.h"
#include "zc_xplatform.h"
#include "zc_util.h"

typedef struct zlog_category_s {
    char name[MAXLEN_PATH + 1];
    size_t name_len;
    unsigned char level_bitmap[32];
    unsigned char level_bitmap_backup[32];
    zc_arraylist_t *fit_rules;
    zc_arraylist_t *fit_rules_backup;
} zlog_category_t;

#endif
