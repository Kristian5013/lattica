// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.


#ifndef LATTICA_QT_INITEXECUTOR_H
#define LATTICA_QT_INITEXECUTOR_H

#include <interfaces/node.h>

#include <exception>

#include <QObject>
#include <QThread>

QT_BEGIN_NAMESPACE
class QString;
QT_END_NAMESPACE

/** Class encapsulating Lattica Core startup and shutdown.
 * Allows running startup and shutdown in a different thread from the UI thread.
 */
class InitExecutor : public QObject
{
    Q_OBJECT
public:
    explicit InitExecutor(interfaces::Node& node);
    ~InitExecutor();

public Q_SLOTS:
    void initialize();
    void shutdown();

Q_SIGNALS:
    void initializeResult(bool success, interfaces::BlockAndHeaderTipInfo tip_info);
    void shutdownResult();
    void runawayException(const QString& message);

private:
    /// Pass fatal exception message to UI thread
    void handleRunawayException(const std::exception* e);

    interfaces::Node& m_node;
    QObject m_context;
    QThread m_thread;
};

#endif // LATTICA_QT_INITEXECUTOR_H
