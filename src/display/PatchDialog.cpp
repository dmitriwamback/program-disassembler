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

    auto* addrLabel = new QLabel(toHexAddr(instruction.address), header);
    addrLabel->setObjectName("patchAddr");

    auto* instructionLabel = new QLabel(QString::fromStdString(instruction.mnemonic + " " + instruction.operands), header);
    instructionLabel->setObjectName("patchInst");

    headerLayout->addWidget(addrLabel);
    headerLayout->addWidget(instructionLabel);
    headerLayout->addStretch();
    root->addWidget(header);

    auto* body = new QWidget(this);
    auto* bodyLayout = new QHBoxLayout(body);

    auto* modeRow = new QHBoxLayout();
    flipButton = new QPushButton("Flip", body);
    nopButton = new QPushButton("Nop", body);
    rawButton = new QPushButton("Raw", body);

    flipButton->setCheckable(true);
    flipButton->setObjectName("modeTab");
    nopButton->setCheckable(true);
    nopButton->setObjectName("modeTab");
    rawButton->setCheckable(true);
    rawButton->setObjectName("modeTab");

    modeRow->addWidget(flipButton);
    modeRow->addWidget(nopButton);
    modeRow->addWidget(rawButton);

    bodyLayout->addLayout(modeRow);

    descriptionLabel = new QLabel(body);
    descriptionLabel->setObjectName("modeDesc");
    descriptionLabel->setWordWrap(true);
    bodyLayout->addWidget(descriptionLabel);

    rawHexEdit = new QLineEdit(body);
    rawHexEdit->setObjectName("rawInput");
    rawHexEdit->setPlaceholderText("e.g. c0 00 00 34");
    rawHexEdit->setText(QString::fromStdString(instruction.bytes));
    bodyLayout->addWidget(rawHexEdit);

    errorLabel = new QLabel(body);
    errorLabel->setObjectName("modalError");
    errorLabel->setWordWrap(true);
    errorLabel->hide();
    bodyLayout->addWidget(errorLabel);

    root->addWidget(body);

    auto* footer = new QWidget(this);
    footer->setObjectName("patchFooter");
    auto* footerLayout = new QHBoxLayout(footer);
    footerLayout->addStretch();
    cancelButton = new QPushButton("Cancel", footer);
    cancelButton->setObjectName("secondaryButton");
    applyButton = new QPushButton("Apply Patch", footer);
    applyButton->setObjectName("primaryButton");
    footerLayout->addWidget(cancelButton);
    footerLayout->addWidget(applyButton);
    root->addWidget(footer);

    connect(flipButton, &QPushButton::clicked, this, [this] { SetMode(Mode::FLIP); });
    connect(nopButton, &QPushButton::clicked, this, [this] { SetMode(Mode::NOP); });
    connect(rawButton, &QPushButton::clicked, this, [this] { SetMode(Mode::RAW); });
    connect(cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    connect(applyButton, &QPushButton::clicked, this, [this] {emit applyRequested(); });

    SetMode(this->instruction.group == InstructionGroup::Jump ? Mode::FLIP : Mode::RAW);
}

void PatchDialog::SetMode(Mode m) {
    mode = m;

    flipButton->setChecked(mode == Mode::FLIP);
    nopButton->setChecked(mode == Mode::NOP);
    rawButton->setChecked(mode == Mode::RAW);
    rawHexEdit->setVisible(mode == Mode::RAW);
    errorLabel->hide();
    RebuildDescription();
}

void PatchDialog::RebuildDescription() {
    if (mode == Mode::FLIP) {
        descriptionLabel->setText("Inverts the branch condition (e.g. cbnz \u2194 cbz, je \u2194 jne). Instruction length is unchanged, so nothing shifts.");
    }
    else if (mode == Mode::NOP) {
        descriptionLabel->setText("Replaces this instruction with no-ops \u2014 execution falls straight through as if the instruction (and any branch it represents) were never there.");
    }
    else if (mode == Mode::RAW) {
        descriptionLabel->setText(QString("Manually overwrite raw bytes. Must be exactly %1 byte%2 to keep every later instruction's offset intact.").arg(instruction.size).arg(instruction.size == 1 ? "" : "s"));
    }
}

bool PatchDialog::ParseRawBytes(std::vector<uint8_t> &outBytes, QString &error) const {
    QString clean = rawHexEdit->text().trimmed();
    clean.replace(QRegularExpression("\\s+"), " ");
    QStringList parts = clean.isEmpty() ? QStringList() : clean.split(' ');

    outBytes.clear();
    for (const QString& part : parts) {
        bool ok = false;
        unsigned int v = part.toUInt(&ok, 16);
        if (!ok || v > 0xff) {
            error = "Invalid hex byte: " + part;
            return false;
        }
        outBytes.push_back(uint8_t(v));
    }

    if (outBytes.size() != instruction.size) {
        error = QString("Must be exactly %1 byte(s) to preserve instruction length.").arg(instruction.size);
        return false;
    }


    return true;
}

void PatchDialog::ShowError(const QString &message) {
    errorLabel->setText(message);
    errorLabel->show();
}

void PatchDialog::SetBusy(bool busy) {
    applyButton->setEnabled(!busy);
    applyButton->setText(busy ? "Applying\u2026" : "Apply Patch");
    cancelButton->setEnabled(!busy);
}