// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <mapport.h>

// Lattica ships no NAT-PMP/PCP/UPnP port mapping, so these are no-ops.
void StartMapPort(bool) {}
void InterruptMapPort() {}
void StopMapPort() {}
