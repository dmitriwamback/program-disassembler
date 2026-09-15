//
// Created by Dmitri on 2026-09-06.
//

#include "MainWindow.h"

#include "PatchDialog.h"
#include "../low_level/Binary.h"
#include "../low_level/Disassembly.h"
#include "../low_level/Patcher.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTreeWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QHeaderView>
#include <QFileDialog>
#include <QFileInfo>
#include <QMessageBox>
#include <QFont>
#include <QFontDatabase>
#include <QStackedWidget>
#include <QSplitter>
#include <QEvent>

#include <fstream>
#include <sstream>
#include <iomanip>

const QColor kAddrColor("#9cdcfe");
const QColor kBytesColor("#6a6a6a");
const QColor kMnemCall("#c586c0");
const QColor kMnemRet("#f14c4c");
const QColor kMnemJump("#569cd6");
const QColor kMnemCmp("#d7ba7d");
const QColor kMnemNormal("#d4d4d4");
const QColor kTargetColor("#c586c0");
const QColor kXrefColor("#4ec9a0");
const QColor kLocalSymColor("#c586c0");
const QColor kExternalSymColor("#4fc1ff");
const QColor kHoverRelatedBg("#264f3a");
const QColor kFnDividerColor("#c586c0");
const QColor kSectionHighlightBg("#4a3f1f");

QFont monoFont(int pointSize = 10) {
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font.setPointSize(pointSize);
    return font;
}

QColor mnemonicColor(InstructionGroup group) {
    switch (group) {
        case InstructionGroup::Call:
            return kMnemCall;
        case InstructionGroup::Ret:
            return kMnemRet;
        case InstructionGroup::Jump:
            return kMnemJump;
        case InstructionGroup::Cmp:
            return kMnemCmp;
        default:
            return kMnemNormal;
    }
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("Disassembler");
    resize(1280, 820);
}