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

    auto* central = new QWidget(this);
    auto* rootLayout = new QVBoxLayout(central);

    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);
    setCentralWidget(central);

    toolbar = new QWidget(central);
    toolbar->setObjectName("toolbar");
    auto* toolbarLayout = new QHBoxLayout(toolbar);
    toolbarLayout->setContentsMargins(10, 6, 10, 6);

    openButton = new QPushButton("Open Binary", toolbar);
    openButton->setObjectName("openButton");

    fileLabel = new QLabel(toolbar);
    fileLabel->setObjectName("fileChip");
    fileLabel->hide();

    formatLabel = new QLabel(toolbar);
    formatLabel->setObjectName("formatChip");
    formatLabel->hide();

    patchCountLabel = new QLabel(toolbar);
    patchCountLabel->setObjectName("patchCountChip");
    patchCountLabel->hide();

    downloadButton = new QPushButton("Download patched binary", toolbar);
    downloadButton->setObjectName("downloadButton");
    downloadButton->hide();

    statusLabel = new QLabel(toolbar);
    statusLabel->setObjectName("statusLabel");

    toolbarLayout->addWidget(openButton);
    toolbarLayout->addWidget(fileLabel);
    toolbarLayout->addWidget(formatLabel);
    toolbarLayout->addStretch();
    toolbarLayout->addWidget(patchCountLabel);
    toolbarLayout->addWidget(downloadButton);
    toolbarLayout->addWidget(statusLabel);

    rootLayout->addWidget(toolbar);

    codesignNote = new QLabel(central);
    codesignNote->setObjectName("codesignNote");
    codesignNote->setTextFormat(Qt::RichText);
    codesignNote->setWordWrap(true);
    codesignNote->hide();
    rootLayout->addWidget(codesignNote);

	auto* stack = new QStackedWidget(central);
	rootLayout->addWidget(stack, 1);
	
	emptyStateLabel = new QLabel("Open a compiled ELF or Mach-O binary to begin analysis.");
	emptyStateLabel->setAlignment(Qt::AlignCenter);
	emptyStateLabel->setObjectName("emptyState");
	stack->addWidget(emptyStateLabel);
 
	workspaceWidget = new QWidget(central);
	auto* workspaceLayout = new QHBoxLayout(workspaceWidget);
	workspaceLayout->setContentsMargins(0, 0, 0, 0);
	workspaceLayout->setSpacing(0);
 
	auto* splitter = new QSplitter(Qt::Horizontal, workspaceWidget);
 
	sidebarTree = new QTreeWidget(splitter);
	sidebarTree->setHeaderHidden(true);
	sidebarTree->setObjectName("sidebarTree");
	splitter->addWidget(sidebarTree);
 
	tabs = new QTabWidget(splitter);
	tabs->setObjectName("mainTabs");
 
	listingTable = new QTableWidget(tabs);
	listingTable->setObjectName("listingTable");
	listingTable->setColumnCount(6);
	listingTable->setHorizontalHeaderLabels({"Address", "Bytes", "Mnemonic", "Operands", "Target", "XREF"});
	listingTable->horizontalHeader()->setStretchLastSection(false);
	listingTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
	listingTable->verticalHeader()->hide();
	listingTable->setShowGrid(false);
	listingTable->setAlternatingRowColors(true);
	listingTable->setEditTriggers(QTableWidget::NoEditTriggers);
	listingTable->setSelectionBehavior(QTableWidget::SelectRows);
	listingTable->setSelectionMode(QTableWidget::SingleSelection);
	listingTable->setMouseTracking(true);
	listingTable->setFont(monoFont());
	listingTable->viewport()->installEventFilter(this);
	tabs->addTab(listingTable, "Listing");
 
	symbolTable = new QTableWidget(tabs);
	symbolTable->setObjectName("symbolTable");
	symbolTable->setColumnCount(3);
	symbolTable->setHorizontalHeaderLabels({"Address", "Size", "Name"});
	symbolTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
	symbolTable->verticalHeader()->hide();
	symbolTable->setEditTriggers(QTableWidget::NoEditTriggers);
	symbolTable->setSelectionBehavior(QTableWidget::SelectRows);
	symbolTable->setFont(monoFont());
	tabs->addTab(symbolTable, "Symbol Table");
 
	sectionsTable = new QTableWidget(tabs);
	sectionsTable->setObjectName("sectionsTable");
	sectionsTable->verticalHeader()->hide();
	sectionsTable->setEditTriggers(QTableWidget::NoEditTriggers);
	sectionsTable->setSelectionBehavior(QTableWidget::SelectRows);
	sectionsTable->setFont(monoFont());
	tabs->addTab(sectionsTable, "Program Headers");
 
	splitter->addWidget(tabs);
	splitter->setStretchFactor(0, 0);
	splitter->setStretchFactor(1, 1);
	splitter->setSizes({220, 1000});
	workspaceLayout->addWidget(splitter);
 
	stack->addWidget(workspaceWidget);
	stack->setCurrentWidget(emptyStateLabel);
 
	connect(openButton, &QPushButton::clicked, this, &MainWindow::OpenBinary);
	connect(downloadButton, &QPushButton::clicked, this, &MainWindow::DownloadPatched);
	connect(listingTable, &QTableWidget::cellClicked, this, &MainWindow::onListingCellClicked);
	connect(listingTable, &QTableWidget::cellEntered, this, &MainWindow::onListingCellEntered);
	connect(sidebarTree, &QTreeWidget::itemClicked, this, &MainWindow::onSidebarItemClicked);
 
	// Keep the empty/workspace stack in sync with whether a binary is loaded.
	connect(this, &MainWindow::destroyed, this, [] {}); // (placeholder to keep lambda-capture patterns consistent below)
	this->setProperty("stackWidget", QVariant::fromValue<void*>(stack));
}
 
bool MainWindow::eventFilter(QObject* obj, QEvent* event) {
	if (obj == listingTable->viewport() && event->type() == QEvent::Leave) {
		ClearHoverHighlights();
	}
	return QMainWindow::eventFilter(obj, event);
}
 
void MainWindow::OpenBinary() {
	QString path = QFileDialog::getOpenFileName(this, "Open Binary", QString(), "All Files (*)");
	if (path.isEmpty()) return;
	LoadFile(path);
}
 
void MainWindow::LoadFile(const QString& path) {
	std::ifstream f(path.toStdString(), std::ios::binary);
	if (!f) {
		statusLabel->setText("Could not open file");
		statusLabel->setProperty("error", true);
		statusLabel->style()->unpolish(statusLabel);
		statusLabel->style()->polish(statusLabel);
		return;
	}
	originalBuffer.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
	patchedBytes = originalBuffer;
	patchRecords.clear();
	fileName = QFileInfo(path).fileName();
 
	auto* stack = static_cast<QStackedWidget*>(this->property("stackWidget").value<void*>());
 
	try {
		parsed = Binary::ParseBinary(originalBuffer);
		RunDisassembly();
		PopulateSidebar();
		PopulateSymbolTable();
		PopulateSections();
		statusLabel->setText("");
		statusLabel->setProperty("error", false);
		if (stack) stack->setCurrentWidget(workspaceWidget);
	} catch (const std::exception& e) {
		parsed.reset();
		statusLabel->setText(QString::fromStdString(e.what()));
		statusLabel->setProperty("error", true);
		if (stack) stack->setCurrentWidget(emptyStateLabel);
	}
	statusLabel->style()->unpolish(statusLabel);
	statusLabel->style()->polish(statusLabel);
 
	UpdateToolbar();
	UpdateCodesignNotes();
}
 
void MainWindow::RunDisassembly() {
	if (!parsed) return;
	try {
		disasm = Disassembly::Disassemble(*parsed);
		PopulateListing();
	}
	catch (const std::exception& e) {
		statusLabel->setText(QString::fromStdString(e.what()));
		statusLabel->setProperty("error", true);
		statusLabel->style()->unpolish(statusLabel);
		statusLabel->style()->polish(statusLabel);
	}
}
 
void MainWindow::UpdateToolbar() {
	if (parsed) {
		fileLabel->setText(fileName);
		fileLabel->show();
		QString fmt = parsed->format == util::BinFormat::Elf ? "ELF" : "MACHO";
		formatLabel->setText(fmt);
		formatLabel->show();
	}
	else {
		fileLabel->hide();
		formatLabel->hide();
	}
 
	if (!patchRecords.empty()) {
		patchCountLabel->setText(QString("%1 patch%2").arg(patchRecords.size()).arg(patchRecords.size() == 1 ? "" : "es"));
		patchCountLabel->show();
		downloadButton->show();
	}
	else {
		patchCountLabel->hide();
		downloadButton->hide();
	}
}
 
void MainWindow::UpdateCodesignNotes() {
	if (!patchRecords.empty() && parsed && parsed->format == util::BinFormat::Macho) {
		QString patchedName = fileName;
		int dot = patchedName.lastIndexOf('.');

		if (dot > 0) {
			patchedName.insert(dot, "_patched");
		}
		else {
			patchedName += "_patched";
		}
 
		codesignNote->setText(
		    QString("<b>macOS binaries need re-signing after patching.</b> Run this on the downloaded file:"
		            "<pre>xattr -d com.apple.quarantine %1\n"
		            "codesign --remove-signature %1\n"
		            "codesign --sign - %1\n"
		            "chmod +x %1</pre>")
		        .arg(patchedName));
		codesignNote->show();
	}
	else {
		codesignNote->hide();
	}
}
 
void MainWindow::PopulateSidebar() {
	sidebarTree->clear();
	if (!parsed) return;
 
	auto* fnRoot = new QTreeWidgetItem(sidebarTree, {QString("Functions (%1)").arg(parsed->symbols.size())});
	fnRoot->setFlags(fnRoot->flags() & ~Qt::ItemIsSelectable);

	if (parsed->symbols.empty()) {
		auto* empty = new QTreeWidgetItem(fnRoot, {"no symbols (stripped)"});

		empty->setFlags(empty->flags() & ~Qt::ItemIsSelectable);
		empty->setForeground(0, QColor("#888888"));
	}
	else {
		for (const util::Symbol& sym : parsed->symbols) {
			QString label = QString("\u0192 ") + QString::fromStdString(sym.name);

			auto* item = new QTreeWidgetItem(fnRoot, {label});
			item->setForeground(0, sym.external ? kExternalSymColor : kLocalSymColor);
			item->setData(0, Qt::UserRole, QVariant::fromValue<qulonglong>(sym.addr));
		}
	}
 
	auto* secRoot = new QTreeWidgetItem(sidebarTree, {QString("Sections (%1)").arg(parsed->sections.size())});
	secRoot->setFlags(secRoot->flags() & ~Qt::ItemIsSelectable);

	for (const util::Section& sec : parsed->sections) {
		QString name = sec.name.empty() ? "(unnamed)" : QString::fromStdString(sec.name);
		auto* item = new QTreeWidgetItem(secRoot, {QString("\u25a4 ") + name});
	}
 
	sidebarTree->expandAll();
}
 
void MainWindow::onSidebarItemClicked(QTreeWidgetItem* item, int /*column*/) {
	QVariant data = item->data(0, Qt::UserRole);
	if (!data.isValid()) return;
	uint64_t addr = data.value<qulonglong>();
	int row = RowForAddress(addr);
	if (row < 0) return;
	tabs->setCurrentWidget(listingTable);
	listingTable->selectRow(row);
	listingTable->scrollToItem(listingTable->item(row, 0));
}
 
int MainWindow::RowForAddress(uint64_t addr) const {
	auto it = addressToRow.find(addr);
	return it == addressToRow.end() ? -1 : it->second;
}
 
void MainWindow::ClearHoverHighlights() {
	if (hoveredHighlightRow < 0) return;
	for (int c = 0; c < listingTable->columnCount(); c++) {
		QTableWidgetItem* item = listingTable->item(hoveredHighlightRow, c);
		if (item) item->setData(Qt::BackgroundRole, QVariant());
	}
	hoveredHighlightRow = -1;
}
 
void MainWindow::onListingCellEntered(int row, int /*column*/) {
	ClearHoverHighlights();
	if (row < 0 || row >= int(instructionIndexForRow.size())) return;
	int idx = instructionIndexForRow[row];
	if (idx < 0) return; // divider row
 
	const Instruction& insn = disasm.instructions[idx];
	if (!insn.target) return;
	int targetRow = RowForAddress(*insn.target);
	if (targetRow < 0) return;
 
	hoveredHighlightRow = targetRow;
	for (int c = 0; c < listingTable->columnCount(); c++) {
		QTableWidgetItem* item = listingTable->item(targetRow, c);
		if (item) item->setBackground(kHoverRelatedBg);
	}
}
 
void MainWindow::onListingCellClicked(int row, int column) {
	if (row < 0 || row >= int(instructionIndexForRow.size())) return;
	int idx = instructionIndexForRow[row];
	if (idx < 0) return; // divider row, not patchable
	OpenPatchDialogForInstruction(idx);
}
 
void MainWindow::OpenPatchDialogForInstruction(int instructionIndex) {
	const Instruction insn = disasm.instructions[instructionIndex]; // copy: patchedBytes/disasm may be replaced below
	selectedAddress = insn.address;
 
	PatchDialog dlg(insn, this);
	bool patchSucceeded = false;
 
	connect(&dlg, &PatchDialog::applyRequested, this, [&]() {
		dlg.SetBusy(true);
		try {
			std::vector<uint8_t> result;
			if (dlg._mode() == PatchDialog::Mode::FLIP) {
				result = Patcher::FlipBranch(patchedBytes, insn.address);
				patchRecords.push_back({insn.address, "flip"});
			}
			else if (dlg._mode() == PatchDialog::Mode::NOP) {
				result = Patcher::NOPRange(patchedBytes, insn.address, insn.size);
				patchRecords.push_back({insn.address, "nop"});
			}
			else {
				std::vector<uint8_t> raw;
				QString err;
				if (!dlg.ParseRawBytes(raw, err)) {
					dlg.ShowError(err);
					dlg.SetBusy(false);
					return;
				}
				result = Patcher::WriteBytes(patchedBytes, insn.address, raw);
				patchRecords.push_back({insn.address, "raw"});
			}
			patchedBytes = std::move(result);
			patchSucceeded = true;
			dlg.accept();
		} catch (const std::exception& e) {
			dlg.ShowError(QString::fromStdString(e.what()));
			dlg.SetBusy(false);
		}
	});
 
	dlg.exec();
 
	if (patchSucceeded && parsed) {
		parsed = Binary::Reslice(*parsed, patchedBytes);
		RunDisassembly();
		UpdateToolbar();
		UpdateCodesignNotes();
		int row = RowForAddress(insn.address);
		if (row >= 0) {
			listingTable->selectRow(row);
			listingTable->scrollToItem(listingTable->item(row, 0));
		}
	}
}
 
void MainWindow::DownloadPatched() {
	if (patchedBytes.empty()) return;
 
	QString suggested = fileName;
	int dot = suggested.lastIndexOf('.');
	if (dot > 0) suggested.insert(dot, "_patched");
	else suggested += "_patched";
	if (suggested.isEmpty()) suggested = "patched.out";
 
	QString path = QFileDialog::getSaveFileName(this, "Save Patched Binary", suggested);
	if (path.isEmpty()) return;
 
	std::ofstream out(path.toStdString(), std::ios::binary);
	out.write(reinterpret_cast<const char*>(patchedBytes.data()), std::streamsize(patchedBytes.size()));
}
 
void MainWindow::PopulateListing() {
	listingTable->clearContents();
	listingTable->setRowCount(0);
	instructionIndexForRow.clear();
	addressToRow.clear();
	hoveredHighlightRow = -1;
 
	if (!parsed) return;
 
	auto addRow = [&]() -> int {
		int row = listingTable->rowCount();
		listingTable->insertRow(row);
		return row;
	};
 
	for (const Function& fn : disasm.functions) {
		int dividerRow = addRow();
		instructionIndexForRow.push_back(-1);
		auto* dividerItem = new QTableWidgetItem(QString::fromStdString(fn.name));
		QFont f = dividerItem->font();
		f.setBold(true);
		dividerItem->setFont(f);
		dividerItem->setForeground(kFnDividerColor);
		dividerItem->setFlags(Qt::ItemIsEnabled);
		listingTable->setItem(dividerRow, 0, dividerItem);
		listingTable->setSpan(dividerRow, 0, 1, listingTable->columnCount());
 
		for (size_t idx : fn.instructionIndices) {
			const Instruction& insn = disasm.instructions[idx];
			int row = addRow();
			instructionIndexForRow.push_back(int(idx));
			addressToRow[insn.address] = row;
 
			auto* addrItem = new QTableWidgetItem(toHexAddr(insn.address));
			addrItem->setForeground(kAddrColor);
			listingTable->setItem(row, 0, addrItem);
 
			auto* bytesItem = new QTableWidgetItem(QString::fromStdString(insn.bytes));
			bytesItem->setForeground(kBytesColor);
			listingTable->setItem(row, 1, bytesItem);
 
			auto* mnemItem = new QTableWidgetItem(QString::fromStdString(insn.mnemonic));
			mnemItem->setForeground(mnemonicColor(insn.group));
			listingTable->setItem(row, 2, mnemItem);
 
			auto* opsItem = new QTableWidgetItem(QString::fromStdString(insn.operands));
			listingTable->setItem(row, 3, opsItem);
 
			QString targetText;
			if (insn.target) {
				targetText = (insn.group == InstructionGroup::Call ? "call to " : "\u2192 ") +
				             QString::fromStdString(insn.targetName);
			}
			auto* targetItem = new QTableWidgetItem(targetText);
			targetItem->setForeground(kTargetColor);
			QFont tf = targetItem->font();
			tf.setItalic(true);
			targetItem->setFont(tf);
			listingTable->setItem(row, 4, targetItem);
 
			auto xrefIt = disasm.xrefs.find(insn.address);
			QString xrefText = (xrefIt != disasm.xrefs.end()) ? QString("XREF[%1]").arg(xrefIt->second.size()) : "";
			auto* xrefItem = new QTableWidgetItem(xrefText);
			xrefItem->setForeground(kXrefColor);
			listingTable->setItem(row, 5, xrefItem);
		}
	}
}
 
void MainWindow::PopulateSymbolTable() {
	symbolTable->clearContents();
	symbolTable->setRowCount(0);
	if (!parsed) return;
 
	symbolTable->setRowCount(int(parsed->symbols.size()));
	int row = 0;
	for (const util::Symbol& sym : parsed->symbols) {
		symbolTable->setItem(row, 0, new QTableWidgetItem(toHexAddr(sym.addr)));
		symbolTable->setItem(row, 1, new QTableWidgetItem(QString::number(sym.size)));
 
		QString name = QString::fromStdString(sym.name);
		if (sym.external) name += "  (imported)";
		auto* nameItem = new QTableWidgetItem(name);
		nameItem->setForeground(sym.external ? kExternalSymColor : kLocalSymColor);
		symbolTable->setItem(row, 2, nameItem);
		row++;
	}
}
 
void MainWindow::PopulateSections() {
	sectionsTable->clearContents();
	sectionsTable->setRowCount(0);
	if (!parsed) return;
 
	bool isMacho = parsed->format == util::BinFormat::Macho;
	QStringList headers = {"Name"};
	if (isMacho) headers << "Segment";
	headers << "Address" << "File Offset" << "Size";
	sectionsTable->setColumnCount(headers.size());
	sectionsTable->setHorizontalHeaderLabels(headers);
	sectionsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
 
	sectionsTable->setRowCount(int(parsed->sections.size()));
	int row = 0;
	for (const util::Section& sec : parsed->sections) {
		int col = 0;
		QString name = sec.name.empty() ? "(unnamed)" : QString::fromStdString(sec.name);
		sectionsTable->setItem(row, col++, new QTableWidgetItem(name));
		if (isMacho) sectionsTable->setItem(row, col++, new QTableWidgetItem(QString::fromStdString(sec.segment)));
		sectionsTable->setItem(row, col++, new QTableWidgetItem(toHexAddr(sec.addr)));
		sectionsTable->setItem(row, col++, new QTableWidgetItem(toHexAddr(sec.offset)));
		sectionsTable->setItem(row, col++, new QTableWidgetItem(QString::number(sec.size)));
 
		bool isCode = sec.name == ".text" || sec.name == "__text";
		if (isCode) {
			for (int c = 0; c < sectionsTable->columnCount(); c++) {
				sectionsTable->item(row, c)->setBackground(kSectionHighlightBg);
			}
		}
		row++;
	}
}
 