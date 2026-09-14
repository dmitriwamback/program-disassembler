//
// Created by Dmitri on 2026-09-06.
//

#ifndef DISASSEMBLER_PATCHDIALOG_H
#define DISASSEMBLER_PATCHDIALOG_H

#include <QDialog>
#include <QString>
#include <cstdint>
#include "../low_level/Disassembly.h"

class QLabel;
class QPushButton;
class QLineEdit;
class QButtonGroup;
class QStackedWidget;

class PatchDialog: public QDialog {
    Q_OBJECT
public:
    enum class Mode { FLIP, NOP, RAW };

    explicit PatchDialog(const Instruction& instruction, QWidget* parent = 0);
    Mode _mode() const { return mode; }

    bool ParseRawBytes(std::vector<uint8_t>& outBytes, QString& error) const;
    void ShowError(const QString& message);
    void SetBusy(bool busy);

signals:
    void ApplyRequested();

private:
    void SetMode(Mode mode);
    void RebuildDescription();
    QString hexAddress(uint64_t address);

    Instruction instruction;
    Mode mode;

    QPushButton* flipButton;
    QPushButton* nopButton;
    QPushButton* rawButton;
    QLabel* descriptionLabel;
    QLineEdit* rawHexEdit;
    QLabel* errorLabel;
    QPushButton* applyButton;
    QPushButton* cancelButton;
};

#endif //DISASSEMBLER_PATCHDIALOG_H
