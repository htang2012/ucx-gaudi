/**
 * Copyright (c) 2024, Habana Labs Ltd. an Intel Company
 */

#ifndef UCT_GAUDI_H
#define UCT_GAUDI_H

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>
#include <habanalabs/hlthunk.h>

BEGIN_C_DECLS

/* Forward declarations */
typedef struct uct_gaudi_iface uct_gaudi_iface_t;

/* Include subheaders */
#include "gaudi_md.h"
#include "gaudi_iface.h"

END_C_DECLS

#endif