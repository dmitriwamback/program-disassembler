//
// Created by Dmitri on 2026-09-06.
//

#ifndef DISASSEMBLER_PATCHDIALOG_H
#define DISASSEMBLER_PATCHDIALOG_H

#include <QDialog>
#include <QString>
#include <cstdint>
#include <iomanip>

#include "../low_level/Disassembly.h"

class QLabel;
class QPushButton;
class QLineEdit;
class QButtonGroup;
class QStackedWidget;

inline QString toHexAddr(uint64_t addr) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << addr;
    return QString::fromStdString(ss.str());
}

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
    void applyRequested();

private:
    void SetMode(Mode mode);
    void RebuildDescription();

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
