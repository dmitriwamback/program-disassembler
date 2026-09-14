//
// Created by Dmitri on 2026-09-06.
//

#include "PatchDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QRegularExpression>
#include <sstream>
#include <iomanip>

PatchDialog::PatchDialog(const Instruction& instruction, QWidget *parent) : QDialog(parent) {
    this->instruction = instruction;
    setObjectName("patchDialog");
    setWindowTitle("Patch Instruction");
    setModal(true);
    setMinimumWidth(460);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    auto* header = new QWidget(this);
    header->setObjectName("patchHeader");

    auto* headerLayout = new QHBoxLayout(header);

    auto* addrLabel = new QLabel(hexAddress(instruction.address), header);
    addrLabel->setObjectName("patchAddr");

    auto* instructionLabel = new QLabel(QString::fromStdString(instruction.mnemonic + " " + instruction.operands), header);
    instructionLabel->setObjectName("patchInst");

    headerLayout->addWidget(addrLabel);
    headerLayout->addWidget(instructionLabel);
    headerLayout->addStretch();
    root->addWidget(header);
}