// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_QT_LATTICAADDRESSVALIDATOR_H
#define LATTICA_QT_LATTICAADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class LatticaAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit LatticaAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

/** Lattica address widget validator, checks for a valid lattica address.
 */
class LatticaAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit LatticaAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

#endif // LATTICA_QT_LATTICAADDRESSVALIDATOR_H
