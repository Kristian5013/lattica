// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_UTIL_TASK_RUNNER_H
#define LATTICA_UTIL_TASK_RUNNER_H

#include <cstddef>
#include <functional>

namespace util {

/** @file
 * This header provides an interface and simple implementation for a task
 * runner. Another threaded, serial implementation using a queue is available in
 * the scheduler module's SerialTaskRunner.
 */

class TaskRunnerInterface
{
public:
    virtual ~TaskRunnerInterface() = default;

    /**
     * The callback can either be queued for later/asynchronous/threaded
     * processing, or be executed immediately for synchronous processing.
     */

    virtual void insert(std::function<void()> func) = 0;

    /**
     * Forces the processing of all pending events.
     */
    virtual void flush() = 0;

    /**
     * Returns the number of currently pending events.
     */
    virtual size_t size() = 0;
};

class ImmediateTaskRunner : public TaskRunnerInterface
{
public:
    void insert(std::function<void()> func) override { func(); }
    void flush() override {}
    size_t size() override { return 0; }
};

} // namespace util

#endif // LATTICA_UTIL_TASK_RUNNER_H
