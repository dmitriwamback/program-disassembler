//
// Created by Dmitri on 2026-09-06.
//

#ifndef DISASSEMBLER_MAINWINDOW_H
#define DISASSEMBLER_MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <optional>
#include <vector>
#include <unordered_map>
#include "src/util/binary_types.h"
#include "src/low_level/Disassembly.h"

class QLabel;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;
class QTabWidget;
class QTableWidget;
class QEvent;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private slots:
    void OpenBinary();
    void DownloadPatched();
    void onListingCellClicked(int row, int column);
    void onListingCellEntered(int row, int column);
    void onSidebarItemClicked(QTreeWidgetItem* item, int column);

private:
    struct PatchRecord {
        uint64_t address;
        QString kind;
    };

    void LoadFile(const QString& path);
    void RunDisassembly();
    void PopulateSidebar();
    void PopulateListing();
    void PopulateSymbolTable();
    void PopulateSections();
    void UpdateToolbar();
    void UpdateCodesignNotes();
    void OpenPatchDialogForInstruction(int instructionIndex);
    void ClearHoverHighlights();
    int RowForAddress(uint64_t address) const;

    std::optional<util::ParsedBinary> parsed;
    DisassemblyResult disasm;
    std::vector<uint8_t> originalBuffer;
    std::vector<uint8_t> patchedBytes;
    std::vector<PatchRecord> patchRecords;
    std::optional<uint64_t> selectedAddress;
    QString fileName;

    std::vector<int> instructionIndexForRow;
    std::unordered_map<uint64_t, int> addressToRow;
    int hoveredHighlightRow = -1;

    QWidget* toolbar;
    QPushButton* openButton;
    QLabel* fileLabel;
    QLabel* formatLabel;
    QLabel* patchCountLabel;
    QPushButton* downloadButton;
    QLabel* statusLabel;
    QLabel* codesignNote;

    QTreeWidget* sidebarTree;
    QTabWidget* tabs;
    QTableWidget* listingTable;
    QTableWidget* symbolTable;
    QTableWidget* sectionsTable;
    QLabel* emptyStateLabel;
    QWidget* workspaceWidget;
};


#endif //DISASSEMBLER_MAINWINDOW_H
