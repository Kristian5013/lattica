// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_NETMESSAGEMAKER_H
#define LATTICA_NETMESSAGEMAKER_H

#include <net.h>
#include <serialize.h>

namespace NetMsg {
    template <typename... Args>
    CSerializedNetMsg Make(std::string msg_type, Args&&... args)
    {
        CSerializedNetMsg msg;
        msg.m_type = std::move(msg_type);
        VectorWriter{msg.data, 0, std::forward<Args>(args)...};
        return msg;
    }
} // namespace NetMsg

#endif // LATTICA_NETMESSAGEMAKER_H