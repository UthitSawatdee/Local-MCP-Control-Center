from __future__ import annotations

import csv
from pathlib import Path

from .conftest import add_scope, allow_capabilities, enable_tools


def _apply_document_edit(broker, tool: str, args: dict) -> dict:
    result = broker.invoke(tool, args)
    assert result["status"] == "ok", result
    assert result["executed"] is True
    return result


def test_csv_transform_is_allowlisted_and_neutralizes_formula(broker, workspace: Path) -> None:
    target = workspace / "items.csv"
    with target.open("w", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerows([["name", "value"], ["one", "1"]])
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read", "write")
    enable_tools(broker, "csv_transform")

    _apply_document_edit(
        broker,
        "csv_transform",
        {
            "scope_id": "test-scope",
            "relative_path": "items.csv",
            "operation": "append_rows",
            "rows": [["two", "=NETWORK()"]],
        },
    )

    with target.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    assert rows[-1] == ["two", "'=NETWORK()"]


def test_xlsx_and_docx_operations_use_format_adapters(broker, workspace: Path) -> None:
    from docx import Document
    from openpyxl import Workbook, load_workbook

    workbook_path = workspace / "book.xlsx"
    workbook = Workbook()
    workbook.active.title = "Data"
    workbook.save(workbook_path)

    document_path = workspace / "letter.docx"
    document = Document()
    document.add_paragraph("Hello customer")
    document.save(document_path)

    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read", "write")
    enable_tools(broker, "xlsx_edit", "docx_edit")

    _apply_document_edit(
        broker,
        "xlsx_edit",
        {
            "scope_id": "test-scope",
            "relative_path": "book.xlsx",
            "operation": "update_cells",
            "updates": [{"sheet": "Data", "cell": "A1", "value": "Approved"}],
        },
    )
    saved = load_workbook(workbook_path, data_only=False)
    assert saved["Data"]["A1"].value == "Approved"

    _apply_document_edit(
        broker,
        "docx_edit",
        {
            "scope_id": "test-scope",
            "relative_path": "letter.docx",
            "operation": "replace_text",
            "old": "customer",
            "new": "partner",
        },
    )
    edited = Document(document_path)
    assert edited.paragraphs[0].text == "Hello partner"
