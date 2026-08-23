// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <node/context.h>

#include <addrman.h>
#include <banman.h>
#include <interfaces/chain.h>
#include <interfaces/mining.h>
#include <kernel/context.h>
#include <key.h>
#include <net.h>
#include <net_processing.h>
#include <netgroup.h>
#include <node/kernel_notifications.h>
#include <node/warnings.h>
#include <policy/fees/estimator_man.h>
#include <scheduler.h>
#include <torcontrol.h>
#include <txmempool.h>
#include <validation.h>
#include <validationinterface.h>

namespace node {
NodeContext::NodeContext() = default;
NodeContext::~NodeContext() = default;
} // namespace node
