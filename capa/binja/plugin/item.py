# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from typing import Optional

import binaryninja as bn

from .qt_compat import Qt, QtGui, QtWidgets

QColor = QtGui.QColor
QFont = QtGui.QFont
QTreeWidgetItem = QtWidgets.QTreeWidgetItem

TREE_ROLE_ADDRESS = int(Qt.ItemDataRole.UserRole)
TREE_ROLE_ADDRESS_KIND = int(Qt.ItemDataRole.UserRole) + 1
TREE_ROLE_TOOLTIP = int(Qt.ItemDataRole.UserRole) + 2

COLOR_ADDRESS = QColor(37, 147, 215)
COLOR_FEATURE = QColor(79, 121, 66)


def info_to_name(display: str) -> str:
    try:
        return display.split("(")[1].rstrip(")")
    except IndexError:
        return ""


def address_to_text(address_value: Optional[int], address_kind: Optional[str] = "absolute") -> str:
    if address_value is None:
        return ""

    if address_kind == "file-offset":
        return f"file+0x{int(address_value):X}"

    return f"0x{int(address_value):X}"


def set_item_bold(item: QTreeWidgetItem, column: int = 0) -> None:
    font = item.font(column)
    font.setBold(True)
    item.setFont(column, font)


def set_item_mono(item: QTreeWidgetItem, column: int, *, bold: bool = False) -> None:
    font = QFont("Courier")
    font.setBold(bold)
    item.setFont(column, font)


def set_program_tree_style(item: QTreeWidgetItem, *, feature: bool = False, bold: bool = False) -> None:
    if bold:
        set_item_bold(item, 0)

    if feature:
        item.setForeground(0, COLOR_FEATURE)

    if item.text(1):
        item.setForeground(1, COLOR_ADDRESS)
        set_item_mono(item, 1, bold=True)

    if item.text(2):
        set_item_mono(item, 2)


def format_match_count(count: int) -> str:
    suffix = "match" if count == 1 else "matches"
    return f"({count} {suffix})"


def normalize_address_display(
    address: str,
    kind: str,
    address_value: Optional[int],
    navigation_kind: Optional[str],
) -> tuple[str, str, Optional[int], Optional[str]]:
    if address:
        return address, kind, address_value, navigation_kind

    if address_value is None:
        return address, kind, address_value, navigation_kind

    if navigation_kind == "file-offset":
        return f"file+0x{address_value:X}", kind or "file offset", address_value, navigation_kind

    return f"0x{address_value:X}", kind or "absolute", address_value, navigation_kind


def format_bytes_preview(data: bytes, width: int = 32) -> str:
    if not data:
        return ""

    return " ".join(f"{byte:02X}" for byte in data[:width])


def preview_address_for_view(
    bv: Optional[bn.BinaryView],
    address_value: Optional[int],
    address_kind: Optional[str],
) -> Optional[int]:
    if bv is None or address_value is None:
        return None

    if address_kind == "absolute":
        return int(address_value)

    if address_kind == "file-offset":
        try:
            mapped = bv.get_address_for_data_offset(int(address_value))
        except Exception:
            mapped = None
        return int(mapped) if mapped is not None else None

    return None


def preview_disassembly(
    bv: Optional[bn.BinaryView],
    address_value: Optional[int],
    address_kind: Optional[str],
) -> str:
    target = preview_address_for_view(bv, address_value, address_kind)
    if target is None:
        return ""

    try:
        return bv.get_disassembly(target) or ""
    except Exception:
        return ""


def preview_bytes(
    bv: Optional[bn.BinaryView],
    address_value: Optional[int],
    address_kind: Optional[str],
) -> str:
    target = preview_address_for_view(bv, address_value, address_kind)
    if target is None:
        return ""

    try:
        data = bv.read(target, 32)
    except Exception:
        return ""

    return format_bytes_preview(data or b"")


class CapaExplorerDataItem(QTreeWidgetItem):
    def __init__(
        self,
        parent,
        data: list[str],
        *,
        can_check: bool = True,
        address_value: Optional[int] = None,
        address_kind: Optional[str] = None,
        tooltip: str = "",
        feature: bool = False,
        bold: bool = False,
    ) -> None:
        super().__init__(parent, data)

        self._can_check = can_check
        self._source = tooltip

        self.setTextAlignment(1, int(Qt.AlignLeft | Qt.AlignVCenter))
        self.setTextAlignment(2, int(Qt.AlignLeft | Qt.AlignVCenter))

        flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if can_check:
            flags |= Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsAutoTristate
        self.setFlags(flags)

        if can_check:
            self.setCheckState(0, Qt.Unchecked)

        if address_value is not None:
            self.setData(0, TREE_ROLE_ADDRESS, int(address_value))
        if address_kind is not None:
            self.setData(0, TREE_ROLE_ADDRESS_KIND, address_kind)
        if tooltip:
            self.setToolTip(0, tooltip)
            self.setData(0, TREE_ROLE_TOOLTIP, tooltip)

        set_program_tree_style(self, feature=feature, bold=bold)

    def canCheck(self) -> bool:
        return self._can_check

    @property
    def info(self) -> str:
        return self.text(0)

    @property
    def location(self) -> Optional[int]:
        value = self.data(0, TREE_ROLE_ADDRESS)
        return int(value) if value is not None else None

    @property
    def location_kind(self) -> Optional[str]:
        value = self.data(0, TREE_ROLE_ADDRESS_KIND)
        return str(value) if value is not None else None

    @property
    def details(self) -> str:
        return self.text(2)

    @property
    def source(self) -> str:
        return self._source

    def __str__(self) -> str:
        return " ".join(text for text in (self.text(0), self.text(1), self.text(2)) if text)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, QTreeWidgetItem):
            return super().__lt__(other)

        tree = self.treeWidget()
        column = tree.sortColumn() if tree is not None else 0

        if column == 1:
            left = self.data(0, TREE_ROLE_ADDRESS)
            right = other.data(0, TREE_ROLE_ADDRESS)
            if left is not None and right is not None:
                return int(left) < int(right)

        return (self.text(column) or "").lower() < (other.text(column) or "").lower()


class CapaExplorerRuleItem(CapaExplorerDataItem):
    def __init__(self, parent, name: str, namespace: str, count: int, source: str, *, can_check: bool = True) -> None:
        display = f"{name} {format_match_count(count)}" if count > 1 else name
        super().__init__(
            parent,
            [display, "", namespace],
            can_check=can_check,
            tooltip=source,
            bold=True,
        )


class CapaExplorerRuleMatchItem(CapaExplorerDataItem):
    def __init__(self, parent, display: str, *, source: str = "", details: str = "", can_check: bool = True) -> None:
        super().__init__(
            parent,
            [display, "", details],
            can_check=can_check,
            tooltip=source,
            bold=True,
        )


class CapaExplorerFunctionItem(CapaExplorerDataItem):
    fmt = "function(%s)"

    def __init__(
        self,
        parent,
        function_name: str,
        *,
        display: Optional[str] = None,
        address_value: Optional[int] = None,
        address_kind: Optional[str] = "absolute",
        address_text: str = "",
        can_check: bool = True,
    ) -> None:
        super().__init__(
            parent,
            [display or (self.fmt % function_name), address_text or address_to_text(address_value, address_kind), ""],
            can_check=can_check,
            address_value=address_value,
            address_kind=address_kind,
            bold=True,
        )

    @property
    def info(self) -> str:
        display = info_to_name(super().info)
        return display if display else super().info


class CapaExplorerSubscopeItem(CapaExplorerDataItem):
    fmt = "subscope(%s)"

    def __init__(self, parent, scope: str, *, can_check: bool = True) -> None:
        super().__init__(parent, [self.fmt % scope, "", ""], can_check=can_check, bold=True)


class CapaExplorerBlockItem(CapaExplorerDataItem):
    fmt = "basic block(loc_%08X)"

    def __init__(
        self,
        parent,
        label: str,
        *,
        address_text: str = "",
        address_value: Optional[int] = None,
        address_kind: Optional[str] = None,
        can_check: bool = True,
    ) -> None:
        if label == "basic block" and address_value is not None:
            label = self.fmt % int(address_value)

        super().__init__(
            parent,
            [label, address_text, ""],
            can_check=can_check,
            address_value=address_value,
            address_kind=address_kind,
            bold=True,
        )


class CapaExplorerInstructionItem(CapaExplorerBlockItem):
    fmt = "instruction(loc_%08X)"

    def __init__(
        self,
        parent,
        *,
        address_text: str = "",
        address_value: Optional[int] = None,
        address_kind: Optional[str] = None,
        can_check: bool = True,
    ) -> None:
        super().__init__(
            parent,
            self.fmt % int(address_value) if address_value is not None else "instruction",
            address_text=address_text,
            address_value=address_value,
            address_kind=address_kind,
            can_check=can_check,
        )


class CapaExplorerDefaultItem(CapaExplorerDataItem):
    def __init__(
        self,
        parent,
        display: str,
        *,
        details: str = "",
        address_text: str = "",
        address_value: Optional[int] = None,
        address_kind: Optional[str] = None,
        can_check: bool = True,
        bold: bool = True,
    ) -> None:
        super().__init__(
            parent,
            [display, address_text, details],
            can_check=can_check,
            address_value=address_value,
            address_kind=address_kind,
            bold=bold,
        )


class CapaExplorerFeatureItem(CapaExplorerDataItem):
    def __init__(
        self,
        parent,
        display: str,
        *,
        details: str = "",
        address_text: str = "",
        address_value: Optional[int] = None,
        address_kind: Optional[str] = None,
        source: str = "",
        can_check: bool = True,
        bold: bool = True,
    ) -> None:
        super().__init__(
            parent,
            [display, address_text, details],
            can_check=can_check,
            address_value=address_value,
            address_kind=address_kind,
            tooltip=source,
            feature=True,
            bold=bold,
        )


class CapaExplorerInstructionFeatureItem(CapaExplorerFeatureItem):
    def __init__(
        self,
        parent,
        display: str,
        *,
        bv: Optional[bn.BinaryView] = None,
        details: str = "",
        address_text: str = "",
        address_value: Optional[int] = None,
        address_kind: Optional[str] = None,
        source: str = "",
        can_check: bool = True,
        bold: bool = True,
    ) -> None:
        preview = preview_disassembly(bv, address_value, address_kind)
        super().__init__(
            parent,
            display,
            details=preview or details,
            address_text=address_text,
            address_value=address_value,
            address_kind=address_kind,
            source=source,
            can_check=can_check,
            bold=bold,
        )


class CapaExplorerByteFeatureItem(CapaExplorerFeatureItem):
    def __init__(
        self,
        parent,
        display: str,
        *,
        bv: Optional[bn.BinaryView] = None,
        details: str = "",
        address_text: str = "",
        address_value: Optional[int] = None,
        address_kind: Optional[str] = None,
        source: str = "",
        can_check: bool = True,
        bold: bool = True,
    ) -> None:
        preview = preview_bytes(bv, address_value, address_kind)
        super().__init__(
            parent,
            display,
            details=preview or details,
            address_text=address_text,
            address_value=address_value,
            address_kind=address_kind,
            source=source,
            can_check=can_check,
            bold=bold,
        )


class CapaExplorerStringFeatureItem(CapaExplorerFeatureItem):
    def __init__(
        self,
        parent,
        display: str,
        *,
        details: str = "",
        address_text: str = "",
        address_value: Optional[int] = None,
        address_kind: Optional[str] = None,
        source: str = "",
        can_check: bool = True,
        bold: bool = True,
    ) -> None:
        super().__init__(
            parent,
            display,
            details=details,
            address_text=address_text,
            address_value=address_value,
            address_kind=address_kind,
            source=source,
            can_check=can_check,
            bold=bold,
        )
