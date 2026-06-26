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

from .item import (
    CapaExplorerBlockItem,
    CapaExplorerByteFeatureItem,
    CapaExplorerDefaultItem,
    CapaExplorerFeatureItem,
    CapaExplorerFunctionItem,
    CapaExplorerInstructionFeatureItem,
    CapaExplorerInstructionItem,
    CapaExplorerRuleItem,
    CapaExplorerRuleMatchItem,
    CapaExplorerStringFeatureItem,
    TREE_ROLE_ADDRESS,
    TREE_ROLE_ADDRESS_KIND,
    normalize_address_display,
)
from .proxy import CapaExplorerSearchProxy
from .qt_compat import Qt, QtGui, QtWidgets

QAbstractItemView = QtWidgets.QAbstractItemView
QApplication = QtWidgets.QApplication
QHeaderView = QtWidgets.QHeaderView
QMenu = QtWidgets.QMenu
QTreeWidget = QtWidgets.QTreeWidget
QTreeWidgetItem = QtWidgets.QTreeWidgetItem

MAX_SECTION_SIZE = 750


class CapaExplorerProgramAnalysisView(QTreeWidget):
    def __init__(self, model, navigate_to_address, set_highlight, rename_function, parent=None):
        super().__init__(parent)

        self.model = model
        self._navigate_to_address_cb = navigate_to_address
        self._set_highlight_cb = set_highlight
        self._rename_function_cb = rename_function
        self._search_proxy = CapaExplorerSearchProxy()
        self._updating = False

        self._get_function_start = None
        self._get_function_name = None
        self._address_display_parts = None
        self._bv = None

        self.setColumnCount(3)
        self.setHeaderLabels(["Rule Information", "Address", "Details"])
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)
        self.setExpandsOnDoubleClick(True)
        self.setIndentation(18)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.setStyleSheet("QTreeWidget::item { padding-top: 4px; padding-bottom: 4px; }")
        self.setSortingEnabled(True)

        self.header().setSectionResizeMode(0, QHeaderView.Interactive)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(2, QHeaderView.Stretch)

        self.itemChanged.connect(self.slot_item_changed)
        self.itemDoubleClicked.connect(self.slot_item_double_clicked)
        self.customContextMenuRequested.connect(self.slot_custom_context_menu_requested)

    def is_updating(self) -> bool:
        return self._updating

    def reset_view(self) -> None:
        self.clear()

    def resize_tree(self) -> None:
        header = self.header()
        self.resizeColumnToContents(0)
        self.resizeColumnToContents(1)

        if header.sectionSize(0) > MAX_SECTION_SIZE:
            header.resizeSection(0, MAX_SECTION_SIZE)

        header.resizeSection(1, max(header.sectionSize(1), 110))

    def load_results(
        self,
        doc,
        *,
        bv,
        group_by_function: bool,
        include_location,
        get_function_start,
        get_function_name,
        address_display_parts,
    ) -> None:
        self._bv = bv
        self._get_function_start = get_function_start
        self._get_function_name = get_function_name
        self._address_display_parts = address_display_parts

        sorting_enabled = self.isSortingEnabled()
        if sorting_enabled:
            self.setSortingEnabled(False)

        self._updating = True
        try:
            self.clear()

            if group_by_function:
                self._render_by_function(doc, include_location)
            else:
                self._render_by_program(doc, include_location)
        finally:
            self._updating = False
            if sorting_enabled:
                self.setSortingEnabled(True)

        self.expandToDepth(1)
        self.resize_tree()

    def apply_text_filter(self, text: str) -> None:
        self._search_proxy.set_query(text)
        root = self.invisibleRootItem()

        def visit(item: QTreeWidgetItem) -> bool:
            child_visible = False
            for index in range(item.childCount()):
                child_visible = visit(item.child(index)) or child_visible

            visible = self._search_proxy.accepts_columns(item.text(column) for column in range(item.columnCount()))
            visible = visible or child_visible
            item.setHidden(not visible)
            return visible

        for index in range(root.childCount()):
            visit(root.child(index))

    def clear_selections(self) -> None:
        self._updating = True
        try:
            root = self.invisibleRootItem()
            for index in range(root.childCount()):
                self._set_item_checked_recursive(root.child(index), False)
        finally:
            self._updating = False

    def _render_by_function(self, doc, include_location) -> None:
        grouped = self.model.collect_rules_by_function(doc, include_location, self._get_function_start)
        if not grouped:
            CapaExplorerDefaultItem(self, "No rule matches found for the current view.", can_check=False, bold=True)
            return

        for function_start in sorted(grouped):
            function_name = self._get_function_name(function_start)
            function_item = CapaExplorerFunctionItem(
                self,
                function_name,
                address_value=function_start,
                address_kind="absolute",
                can_check=False,
            )

            for rule, count in grouped[function_start]:
                rule_item = CapaExplorerRuleItem(
                    function_item,
                    rule.meta.name,
                    rule.meta.namespace or "",
                    count,
                    rule.source,
                    can_check=False,
                )
                rule_item.setExpanded(True)

    def _render_by_program(self, doc, include_location) -> None:
        import capa.rules

        for rule, matches in self.model.collect_rules_by_program(doc, include_location):
            rule_item = CapaExplorerRuleItem(
                self,
                rule.meta.name,
                rule.meta.namespace or "",
                len(matches),
                rule.source,
            )

            for location, match in matches:
                if capa.rules.Scope.FILE in rule.meta.scopes:
                    parent_item = rule_item
                elif capa.rules.Scope.FUNCTION in rule.meta.scopes:
                    parent_item = self._create_function_tree_item(rule_item, location)
                elif capa.rules.Scope.BASIC_BLOCK in rule.meta.scopes:
                    address_text, address_value, address_kind = self._address_item_values(location)
                    parent_item = CapaExplorerBlockItem(
                        rule_item,
                        "basic block",
                        address_text=address_text,
                        address_value=address_value,
                        address_kind=address_kind,
                    )
                elif capa.rules.Scope.INSTRUCTION in rule.meta.scopes:
                    address_text, address_value, address_kind = self._address_item_values(location)
                    parent_item = CapaExplorerInstructionItem(
                        rule_item,
                        address_text=address_text,
                        address_value=address_value,
                        address_kind=address_kind,
                    )
                else:
                    parent_item = rule_item

                self._render_match_tree(parent_item, match, doc)

        if self.topLevelItemCount() == 0:
            CapaExplorerDefaultItem(self, "No rule matches found for the current view.", can_check=False, bold=True)

    def _create_function_tree_item(self, parent: QTreeWidgetItem, location) -> QTreeWidgetItem:
        address, kind, address_value, address_kind = self._address_display_parts(location)
        if address_kind == "absolute" and address_value is not None:
            function_start = self._get_function_start(address_value)
            if function_start is not None:
                function_name = self._get_function_name(function_start)
                return CapaExplorerFunctionItem(
                    parent,
                    function_name,
                    address_value=function_start,
                    address_kind="absolute",
                )

        address, kind, address_value, address_kind = normalize_address_display(
            address,
            kind,
            address_value,
            address_kind,
        )
        return CapaExplorerFunctionItem(
            parent,
            "function",
            display="function",
            address_value=address_value,
            address_kind=address_kind,
            address_text=address,
        )

    def _render_match_tree(self, parent: QTreeWidgetItem, match, doc) -> None:
        import capa.render.result_document as rd

        if not match.success:
            return

        if isinstance(match.node, rd.StatementNode):
            statement = match.node.statement
            if (
                isinstance(statement, rd.CompoundStatement)
                and statement.type == rd.CompoundStatementType.OPTIONAL
                and not any(child.success for child in match.children)
            ):
                return

            parent_item = self._render_statement_node(parent, match, doc)
        else:
            parent_item = self._render_feature_node(parent, match, doc)

        for child in match.children:
            self._render_match_tree(parent_item, child, doc)

    def _render_statement_node(self, parent: QTreeWidgetItem, match, doc) -> QTreeWidgetItem:
        import capa.render.result_document as rd

        statement = match.node.statement
        locations = [location.to_capa() for location in match.locations]

        if isinstance(statement, rd.CompoundStatement):
            display = statement.type
            if statement.description:
                display += f" ({statement.description})"
            return CapaExplorerRuleMatchItem(parent, display)

        if isinstance(statement, rd.SomeStatement):
            display = f"{statement.count} or more"
            if statement.description:
                display += f" ({statement.description})"
            return CapaExplorerRuleMatchItem(parent, display)

        if isinstance(statement, rd.RangeStatement):
            display = f"count({self.model.feature_to_display(statement.child)}): "
            if statement.max == statement.min:
                display += f"{statement.min}"
            elif statement.min == 0:
                display += f"{statement.max} or fewer"
            elif statement.max == ((1 << 64) - 1):
                display += f"{statement.min} or more"
            else:
                display += f"between {statement.min} and {statement.max}"

            if statement.description:
                display += f" ({statement.description})"

            range_item = CapaExplorerFeatureItem(parent, display, can_check=True, bold=True)
            for location in locations:
                self._render_feature_instance(range_item, match, statement.child, location, doc, display=display)
            return range_item

        if isinstance(statement, rd.SubscopeStatement):
            display = str(statement.scope)
            if statement.description:
                display += f" ({statement.description})"
            return CapaExplorerRuleMatchItem(parent, display)

        return CapaExplorerRuleMatchItem(parent, str(statement.type))

    def _render_feature_node(self, parent: QTreeWidgetItem, match, doc) -> QTreeWidgetItem:
        feature = match.node.feature
        locations = [location.to_capa() for location in match.locations]
        display = self.model.feature_to_display(feature)

        if len(locations) <= 1:
            location = locations[0] if locations else None
            return self._render_feature_instance(parent, match, feature, location, doc, display=display)

        feature_item = CapaExplorerFeatureItem(parent, display, can_check=True, bold=True)
        for location in locations:
            self._render_feature_instance(feature_item, match, feature, location, doc, display=display)
        return feature_item

    def _render_feature_instance(self, parent, match, feature, location, doc, *, display: str) -> QTreeWidgetItem:
        tooltip = ""
        details = ""
        address, address_kind, address_value, navigation_kind = self._address_display_parts(location)
        address, address_kind, address_value, navigation_kind = normalize_address_display(
            address,
            address_kind,
            address_value,
            navigation_kind,
        )

        import capa.features.common
        import capa.features.freeze.features as frzf

        feature_kind = self.model.feature_kind(feature)

        if feature_kind == "match" and doc is not None and isinstance(feature, frzf.MatchFeature):
            matched_rule = doc.rules.get(feature.match)
            if matched_rule is not None:
                tooltip = matched_rule.source
            return CapaExplorerRuleMatchItem(parent, display, source=tooltip)

        if feature_kind == "string" and isinstance(feature, frzf.StringFeature):
            details = f"\"{capa.features.common.escape_string(feature.string)}\""
            return CapaExplorerStringFeatureItem(
                parent,
                display,
                address_text=address,
                details=details,
                address_value=address_value,
                address_kind=navigation_kind,
                source=tooltip,
            )

        if feature_kind == "string" and isinstance(feature, (frzf.SubstringFeature, frzf.RegexFeature)):
            details = self.model.capture_details_for_location(match, location)
            return CapaExplorerStringFeatureItem(
                parent,
                display,
                address_text=address,
                details=details,
                address_value=address_value,
                address_kind=navigation_kind,
                source=tooltip,
            )

        if feature_kind == "block":
            return CapaExplorerBlockItem(
                parent,
                "basic block",
                address_text=address,
                address_value=address_value,
                address_kind=navigation_kind,
            )

        if feature_kind == "instruction":
            return CapaExplorerInstructionFeatureItem(
                parent,
                display,
                bv=self._bv,
                address_text=address,
                details="",
                address_value=address_value,
                address_kind=navigation_kind,
                source=tooltip,
            )

        if feature_kind == "bytes":
            return CapaExplorerByteFeatureItem(
                parent,
                display,
                bv=self._bv,
                address_text=address,
                details="",
                address_value=address_value,
                address_kind=navigation_kind,
                source=tooltip,
            )

        return CapaExplorerFeatureItem(
            parent,
            display,
            address_text=address,
            details=details,
            address_value=address_value,
            address_kind=navigation_kind,
            source=tooltip,
        )

    def _address_item_values(self, location) -> tuple[str, Optional[int], Optional[str]]:
        address, kind, address_value, navigation_kind = self._address_display_parts(location)
        address, _, address_value, navigation_kind = normalize_address_display(address, kind, address_value, navigation_kind)
        return address, address_value, navigation_kind

    def _set_item_checked_recursive(self, item: QTreeWidgetItem, checked: bool) -> None:
        try:
            children = [item.child(index) for index in range(item.childCount())]
            address_value = item.data(0, TREE_ROLE_ADDRESS)
            address_kind = item.data(0, TREE_ROLE_ADDRESS_KIND)
            item.setCheckState(0, Qt.Checked if checked else Qt.Unchecked)
            self._set_highlight_cb(address_value, address_kind, checked)
        except RuntimeError:
            return

        for child in children:
            if child is not None:
                self._set_item_checked_recursive(child, checked)

    def _copy_column(self, item: QTreeWidgetItem, column: int) -> None:
        QApplication.clipboard().setText(item.text(column))

    def _copy_row(self, item: QTreeWidgetItem) -> None:
        QApplication.clipboard().setText(str(item))

    def new_action(self, display, data, slot):
        action = QtGui.QAction(display, self)
        action.setData(data)
        action.triggered.connect(lambda checked=False, current=action: slot(current))
        return action

    def load_default_context_menu_actions(self, data):
        for action in (
            ("Copy column", data, self.slot_copy_column),
            ("Copy row", data, self.slot_copy_row),
        ):
            yield self.new_action(*action)

    def load_function_context_menu_actions(self, data):
        for action in (("Rename function", data, self.slot_rename_function),):
            yield self.new_action(*action)

        yield from self.load_default_context_menu_actions(data)

    def load_default_context_menu(self, pos, item, column):
        menu = QMenu(self)
        for action in self.load_default_context_menu_actions((pos, item, column)):
            menu.addAction(action)
        return menu

    def load_function_item_context_menu(self, pos, item, column):
        menu = QMenu(self)
        for action in self.load_function_context_menu_actions((pos, item, column)):
            menu.addAction(action)
        return menu

    def show_custom_context_menu(self, menu, pos) -> None:
        if menu is not None:
            menu.exec_(self.viewport().mapToGlobal(pos))

    def slot_copy_column(self, action) -> None:
        _, item, column = action.data()
        self._copy_column(item, max(0, int(column)))

    def slot_copy_row(self, action) -> None:
        _, item, _ = action.data()
        self._copy_row(item)

    def slot_rename_function(self, action) -> None:
        _, item, _ = action.data()
        address_value = item.data(0, TREE_ROLE_ADDRESS)
        address_kind = item.data(0, TREE_ROLE_ADDRESS_KIND)
        if address_value is None or address_kind != "absolute":
            return

        self._rename_function_cb(int(address_value))

    def slot_custom_context_menu_requested(self, pos) -> None:
        item = self.itemAt(pos)
        if item is None:
            return

        column = self.columnAt(pos.x())

        if column == 0 and isinstance(item, CapaExplorerFunctionItem):
            menu = self.load_function_item_context_menu(pos, item, column)
        else:
            menu = self.load_default_context_menu(pos, item, column)

        self.show_custom_context_menu(menu, pos)

    def slot_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        if column != 0 or self._updating:
            return

        try:
            state = item.checkState(0)
        except RuntimeError:
            return

        if state == Qt.PartiallyChecked:
            return

        self._updating = True
        try:
            self.blockSignals(True)
            self._set_item_checked_recursive(item, state == Qt.Checked)
        finally:
            self.blockSignals(False)
            self._updating = False

    def slot_item_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        if column != 1:
            return

        address_value = item.data(0, TREE_ROLE_ADDRESS)
        address_kind = item.data(0, TREE_ROLE_ADDRESS_KIND)
        if address_value is None or address_kind is None:
            return

        self._navigate_to_address_cb(address_value, address_kind)
