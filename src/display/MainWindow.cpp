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
#include <QStackedWidget>
#include <QSplitter>
#include <QEvent>

#include <fstream>
#include <sstream>
#include <iomanip>

