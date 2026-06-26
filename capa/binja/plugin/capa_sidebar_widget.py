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

import json
import logging
from pathlib import Path
from typing import Optional

import binaryninja as bn
from binaryninja.settings import Settings as BNSettings, SettingsScope
from binaryninjaui import (
    SidebarContextSensitivity,
    SidebarWidget,
    SidebarWidgetLocation,
    SidebarWidgetType,
    UIActionHandler,
    UIContext,
)

from .cache import CapaExplorerResultCache, ProgramAnalysisState
from .extractor import (
    AnalysisCancelledError,
    get_capa_import_error_message,
    get_rules_cache_metadata,
    is_capa_available,
    run_program_analysis,
    validate_analysis_document_for_view,
)
from .hooks import CapaExplorerBinjaHooks
from .icon import ICON
from .item import set_item_bold, set_program_tree_style
from .model import CapaExplorerProgramAnalysisModel
from .proxy import CapaExplorerRangeProxy
from .qt_compat import Qt, QtCore, QtGui, QtWidgets
from .view import CapaExplorerProgramAnalysisView

logger = logging.getLogger("capa.binja")

QByteArray = QtCore.QByteArray
QImage = QtGui.QImage
QPixmap = QtGui.QPixmap

QCheckBox = QtWidgets.QCheckBox
QDialog = QtWidgets.QDialog
QDialogButtonBox = QtWidgets.QDialogButtonBox
QFileDialog = QtWidgets.QFileDialog
QFormLayout = QtWidgets.QFormLayout
QHBoxLayout = QtWidgets.QHBoxLayout
QLabel = QtWidgets.QLabel
QLineEdit = QtWidgets.QLineEdit
QMessageBox = QtWidgets.QMessageBox
QProgressDialog = QtWidgets.QProgressDialog
QPushButton = QtWidgets.QPushButton
QStackedWidget = QtWidgets.QStackedWidget
QTabWidget = QtWidgets.QTabWidget
QTreeWidgetItem = QtWidgets.QTreeWidgetItem
QVBoxLayout = QtWidgets.QVBoxLayout
QWidget = QtWidgets.QWidget

PLUGIN_NAME = "FLARE capa explorer"

DEFAULT_STATUS = "Click Analyze to get started..."

PAGE_NO_FILE = 0
PAGE_MAIN = 1

SETTINGS_GROUP = "capa"
SETTINGS_RULE_PATH = "capa.rulesPath"
ANALYSIS_METADATA_KEY = "capa.programAnalysis"

_analysis_cache = CapaExplorerResultCache()


class CapaPluginSettings:
    def __init__(self) -> None:
        self._settings = BNSettings(instance_id="default")
        self._register_group_and_settings()

    def _register_group_and_settings(self) -> None:
        self._settings.register_group(SETTINGS_GROUP, "capa")

        if not self._settings.contains(SETTINGS_RULE_PATH):
            self._settings.register_setting(
                SETTINGS_RULE_PATH,
                json.dumps(
                    {
                        "title": "capa Rules Path",
                        "description": "Local directory containing capa rule files.",
                        "type": "string",
                        "default": "",
                        "ignore": ["SettingsProjectScope", "SettingsResourceScope"],
                    }
                ),
            )

    def get_rules_path(self) -> str:
        return self._settings.get_string(SETTINGS_RULE_PATH)

    def set_rules_path(self, value: str) -> None:
        self._settings.set_string(SETTINGS_RULE_PATH, value, scope=SettingsScope.SettingsUserScope)


settings = CapaPluginSettings()


class CapaSettingsDialog(QDialog):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)

        self.setWindowTitle("capa explorer settings")
        self.setMinimumWidth(540)

        self.edit_rule_path = QLineEdit(settings.get_rules_path())

        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self._on_browse_rules)

        path_row = QHBoxLayout()
        path_row.setContentsMargins(0, 0, 0, 0)
        path_row.addWidget(self.edit_rule_path)
        path_row.addWidget(browse_button)

        path_widget = QWidget()
        path_widget.setLayout(path_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, parent=self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QFormLayout(self)
        layout.addRow("capa rules path", path_widget)
        layout.addWidget(buttons)

    def _on_browse_rules(self) -> None:
        start_dir = self.edit_rule_path.text().strip() or str(Path.home())
        directory = QFileDialog.getExistingDirectory(self, "Please select a capa rules directory", start_dir)
        if directory:
            self.edit_rule_path.setText(directory)

    def value(self) -> str:
        return self.edit_rule_path.text().strip()


class _Task(bn.BackgroundTaskThread):
    def __init__(self, message: str, work, done):
        super().__init__(message, True)
        self._work = work
        self._done = done

    def run(self):
        try:
            result = self._work(self)
            bn.mainthread.execute_on_main_thread(lambda res=result: self._done(res, None))
        except AnalysisCancelledError as error:
            bn.mainthread.execute_on_main_thread(lambda err=error: self._done(None, err))
        except Exception as error:
            logger.exception("[%s] background task failed", PLUGIN_NAME)
            bn.mainthread.execute_on_main_thread(lambda err=error: self._done(None, err))


def open_capa_sidebar() -> bool:
    context = UIContext.activeContext()
    if not context:
        return False

    sidebar = context.sidebar()
    if not sidebar:
        return False

    sidebar.activate(PLUGIN_NAME)
    return True


def _load_icon_image() -> QImage:
    image = QImage()
    if not image.loadFromData(QByteArray(ICON), "PNG") or image.isNull():
        logger.error("[%s] failed to load sidebar icon", PLUGIN_NAME)
    return image


def _load_icon_pixmap(size: int) -> QPixmap:
    pixmap = QPixmap()
    if not pixmap.loadFromData(QByteArray(ICON), "PNG") or pixmap.isNull():
        logger.error("[%s] failed to load sidebar pixmap", PLUGIN_NAME)
        return QPixmap()
    return pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)


def _bv_path(bv: bn.BinaryView | None) -> str:
    try:
        if not bv or not bv.file:
            return ""
        for attr in ("original_filename", "filename"):
            path = getattr(bv.file, attr, None)
            if path:
                return path
        return ""
    except Exception:
        return ""


def _coerce_binary_view(data) -> Optional[bn.BinaryView]:
    return data if isinstance(data, bn.BinaryView) else None


def _binary_view_from_frame(frame) -> Optional[bn.BinaryView]:
    try:
        return _coerce_binary_view(frame.getCurrentBinaryView()) if frame else None
    except Exception:
        return None


def _rules_path_error(rules_path: str) -> Optional[str]:
    path_text = rules_path.strip()
    if not path_text:
        return "Select a local directory containing capa rules before running analysis."

    path = Path(path_text)
    if not path.exists():
        return "The configured capa rules path does not exist."

    if not path.is_dir():
        return "The configured capa rules path must be a directory."

    return None


class CapaExplorerSidebarWidget(SidebarWidget):
    def __init__(self, name: str, frame, data):
        super().__init__(name)

        self._instance_id = id(self)
        self.bv: Optional[bn.BinaryView] = _coerce_binary_view(data) or _binary_view_from_frame(frame)
        self.current_offset: Optional[int] = None
        self._destroyed = False
        self._analysis_status = DEFAULT_STATUS
        self._analysis_state: Optional[ProgramAnalysisState] = None
        self._analysis_task_token = 0
        self._analysis_task: Optional[_Task] = None
        self._analysis_running = False
        self._analysis_progress_dialog: Optional[QProgressDialog] = None
        self._database_refresh_pending = False
        self._deferred_database_refresh: Optional[tuple[str, Optional[bn.BinaryView]]] = None
        self._deferred_database_refresh_scheduled = False
        self._suspend_function_update_refresh = 0
        self._program_highlight_state: dict[tuple[int, int], dict[str, object]] = {}
        self._last_synced_bv_identity: Optional[int] = None
        self._hooks = CapaExplorerBinjaHooks(self._on_binary_view_database_changed)
        self._program_model = CapaExplorerProgramAnalysisModel()
        self._range_proxy = CapaExplorerRangeProxy()

        self.destroyed.connect(self._mark_destroyed)

        self._action_handler = UIActionHandler()
        self._action_handler.setupActionHandler(self)

        self._build_ui()
        self._load_program_analysis_placeholder()
        self._hooks.set_binary_view(self.bv)
        self._update_page()
        self._restore_cached_results()

        logger.debug("[%s] sidebar widget created id=%s bv=%s", PLUGIN_NAME, self._instance_id, _bv_path(self.bv) or "<no file>")

    def _mark_destroyed(self):
        self._destroyed = True
        self._clear_instruction_highlights()
        self._close_analysis_progress_dialog()
        self._hooks.close()
        logger.debug("[%s] sidebar widget destroyed id=%s", PLUGIN_NAME, self._instance_id)

    def _is_alive(self) -> bool:
        if self._destroyed:
            return False
        try:
            self.isVisible()
            return True
        except RuntimeError:
            self._destroyed = True
            return False

    def _build_ui(self):
        root = QVBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._create_no_file_page())
        self.stack.addWidget(self._create_main_page())

        root.addWidget(self.stack)
        self.setLayout(root)

    def _update_page(self) -> None:
        if not self._is_alive():
            return

        self.stack.setCurrentIndex(PAGE_MAIN if self.bv is not None else PAGE_NO_FILE)

    def _create_no_file_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 40, 20, 40)
        layout.addStretch(1)

        logo = QLabel()
        logo.setAlignment(Qt.AlignCenter)
        logo.setPixmap(_load_icon_pixmap(80))
        layout.addWidget(logo)

        layout.addSpacing(18)

        title = QLabel("No File Open")
        title.setAlignment(Qt.AlignCenter)
        title_font = title.font()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        layout.addSpacing(10)

        message = QLabel(
            "The <b>FLARE capa explorer</b> sidebar requires an open file.<br><br>"
            "Open a binary to run <b>Program Analysis</b>."
        )
        message.setAlignment(Qt.AlignCenter)
        message.setWordWrap(True)
        message.setTextFormat(Qt.RichText)
        layout.addWidget(message)

        layout.addStretch(1)
        return page

    def _create_main_page(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(6)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_program_analysis_tab(), "Program Analysis")
        outer.addWidget(self.tabs)

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)

        self.btn_analyze = QPushButton("Analyze")
        self.btn_reset = QPushButton("Reset Selections")
        self.btn_settings = QPushButton("Settings")
        self.btn_save = QPushButton("Save")

        self.btn_analyze.clicked.connect(self._on_analyze_clicked)
        self.btn_reset.clicked.connect(self._on_reset_clicked)
        self.btn_settings.clicked.connect(self._on_settings_clicked)
        self.btn_save.clicked.connect(self._on_save_clicked)

        buttons.addWidget(self.btn_analyze)
        buttons.addWidget(self.btn_reset)
        buttons.addWidget(self.btn_settings)
        buttons.addStretch(3)
        buttons.addWidget(self.btn_save, alignment=Qt.AlignRight)
        outer.addLayout(buttons)

        self.status_label = QLabel(DEFAULT_STATUS)
        self.status_label.setAlignment(Qt.AlignLeft)
        outer.addWidget(self.status_label)

        return page

    def _create_program_analysis_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        controls = QHBoxLayout()
        controls.setContentsMargins(0, 0, 0, 0)

        self.cb_limit_results_by_function = QCheckBox("Limit results to current function")
        self.cb_show_matches_by_function = QCheckBox("Show matches by function")
        self.cb_limit_results_by_function.stateChanged.connect(self._on_limit_results_by_function_changed)
        self.cb_show_matches_by_function.stateChanged.connect(self._on_show_matches_by_function_changed)

        controls.addWidget(self.cb_limit_results_by_function)
        controls.addWidget(self.cb_show_matches_by_function)
        controls.addStretch(1)
        layout.addLayout(controls)

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("search...")
        self.search_bar.setClearButtonEnabled(True)
        self.search_bar.textChanged.connect(self._on_search_changed)
        layout.addWidget(self.search_bar)

        self.program_tree = CapaExplorerProgramAnalysisView(
            self._program_model,
            self._navigate_program_analysis_address,
            self._set_instruction_highlight,
            self._rename_program_analysis_function,
        )
        layout.addWidget(self.program_tree)

        return tab

    def _load_program_analysis_placeholder(self) -> None:
        self._clear_instruction_highlights()
        self.program_tree.reset_view()

        root = QTreeWidgetItem(self.program_tree, ["Program Analysis scaffold", "", "Binary Ninja UI is ready."])
        set_program_tree_style(root, bold=True)
        QTreeWidgetItem(root, ["Click Analyze after configuring your capa rules path", "", ""])
        QTreeWidgetItem(root, ["Use Settings to choose the local rules directory", "", ""])
        root.setExpanded(True)

    def _set_status(self, text: str) -> None:
        self._analysis_status = text
        self.status_label.setText(text)

    def _sync_view_state(self, bv: Optional[bn.BinaryView], *, reset_offset: bool = False) -> None:
        if not self._is_alive():
            return

        previous_bv = self.bv
        self.bv = _coerce_binary_view(bv)
        self._hooks.set_binary_view(self.bv)
        current_identity = id(self.bv) if self.bv is not None else None

        if previous_bv is not self.bv:
            self._clear_instruction_highlights(previous_bv)

        if reset_offset:
            self.current_offset = None
            self._hooks.offset = None
            self._hooks.function_start = None

        self._update_page()
        if current_identity != self._last_synced_bv_identity:
            if self._analysis_task is not None:
                self._analysis_task.cancelled = True
                self._analysis_task_token += 1
                self._analysis_running = False
                self._close_analysis_progress_dialog()

            self.btn_analyze.setEnabled(True)
            self._last_synced_bv_identity = current_identity
            self._restore_cached_results()

        self._set_status(self._analysis_status)

    def _restore_cached_results(self) -> None:
        if self.bv is None:
            self._analysis_state = None
            self._load_program_analysis_placeholder()
            self._analysis_status = DEFAULT_STATUS
            return

        rules_path = settings.get_rules_path().strip()
        cached = _analysis_cache.get(self.bv, rules_path) if rules_path else None
        if cached is None:
            cached = self._load_persisted_analysis_state()

        if cached is None:
            self._analysis_state = None
            self._load_program_analysis_placeholder()
            self._analysis_status = DEFAULT_STATUS
            return

        self._apply_ruleset_compatibility(cached, rules_path)
        self._load_existing_program_analysis(
            ProgramAnalysisState(
                doc=cached.doc,
                rules_path=cached.rules_path,
                rules_count=cached.rules_count,
                limitation_found=cached.limitation_found,
                from_cache=True,
                rules_cache_id=cached.rules_cache_id,
                ruleset_compatible=cached.ruleset_compatible,
            )
        )

    def _apply_ruleset_compatibility(self, state: ProgramAnalysisState, rules_path: str) -> None:
        if not rules_path:
            state.ruleset_compatible = True
            return

        try:
            metadata = get_rules_cache_metadata(rules_path)
            state.ruleset_compatible = bool(state.rules_cache_id) and (
                state.rules_cache_id == str(metadata["rules_cache_id"])
            )
        except Exception:
            logger.exception("[%s] failed to validate cached rules metadata", PLUGIN_NAME)
            state.ruleset_compatible = False

    def _analysis_summary_text(self, state: ProgramAnalysisState) -> str:
        message = f"capa rules: {state.rules_path} ({state.rules_count} rules)"
        if state.from_cache:
            message += f", cached results (created {self._analysis_timestamp_text(state)})"
            if not state.ruleset_compatible:
                message += ", rules changed since cache was created"
        if state.limitation_found:
            message += ", limitation rule matched"
        return message

    def _analysis_timestamp_text(self, state: ProgramAnalysisState) -> str:
        try:
            timestamp = getattr(getattr(state.doc, "meta", None), "timestamp", None)
            if timestamp is None:
                return "unknown time"
            return timestamp.strftime("%Y-%m-%d at %H:%M:%S")
        except Exception:
            return "unknown time"

    def _query_persisted_analysis_payload(self, bv: Optional[bn.BinaryView] = None) -> Optional[dict]:
        bv = _coerce_binary_view(bv) or self.bv
        if bv is None:
            return None

        try:
            payload = bv.query_metadata(ANALYSIS_METADATA_KEY)
        except KeyError:
            return None
        except Exception:
            logger.exception("[%s] failed to query persisted analysis metadata", PLUGIN_NAME)
            return None

        return payload if isinstance(payload, dict) else None

    def _load_persisted_analysis_state(self, bv: Optional[bn.BinaryView] = None) -> Optional[ProgramAnalysisState]:
        bv = _coerce_binary_view(bv) or self.bv
        if bv is None:
            return None

        payload = self._query_persisted_analysis_payload(bv)
        if payload is None:
            return None

        try:
            import capa.render.result_document as rd

            doc = rd.ResultDocument.model_validate_json(payload["doc_json"])
            if not validate_analysis_document_for_view(bv, doc):
                raise ValueError("cached results contain invalid addresses for this BinaryView")

            return ProgramAnalysisState(
                doc=doc,
                rules_path=str(payload.get("rules_path", "")),
                rules_count=int(payload.get("rules_count", 0)),
                limitation_found=bool(payload.get("limitation_found", False)),
                from_cache=True,
                rules_cache_id=str(payload.get("rules_cache_id", "")),
                ruleset_compatible=bool(payload.get("ruleset_compatible", True)),
            )
        except Exception:
            logger.exception("[%s] failed to load persisted analysis metadata", PLUGIN_NAME)
            try:
                bv.remove_metadata(ANALYSIS_METADATA_KEY)
            except Exception:
                logger.exception("[%s] failed to remove invalid persisted analysis metadata", PLUGIN_NAME)
            return None

    def _persist_analysis_state(self, bv: Optional[bn.BinaryView], state: ProgramAnalysisState) -> None:
        bv = _coerce_binary_view(bv)
        if bv is None:
            return

        try:
            bv.store_metadata(
                ANALYSIS_METADATA_KEY,
                {
                    "version": 2,
                    "rules_path": state.rules_path,
                    "rules_count": state.rules_count,
                    "limitation_found": state.limitation_found,
                    "rules_cache_id": state.rules_cache_id,
                    "ruleset_compatible": state.ruleset_compatible,
                    "timestamp": self._analysis_timestamp_text(state),
                    "doc_json": state.doc.model_dump_json(),
                },
            )
        except Exception:
            logger.exception("[%s] failed to persist analysis metadata", PLUGIN_NAME)

    def _load_existing_program_analysis(self, state: ProgramAnalysisState) -> None:
        if self.bv is not None:
            _analysis_cache.put(self.bv, state.rules_path, state)

        self._analysis_state = state
        self._render_current_program_analysis()
        self._set_status(self._analysis_summary_text(state))

    def _prompt_for_existing_program_analysis(self) -> str:
        existing_state = self._analysis_state
        if existing_state is None:
            existing_state = self._load_persisted_analysis_state()

        if existing_state is None:
            return "reanalyze"

        compatible_state = ProgramAnalysisState(
            doc=existing_state.doc,
            rules_path=existing_state.rules_path,
            rules_count=existing_state.rules_count,
            limitation_found=existing_state.limitation_found,
            from_cache=True,
            rules_cache_id=existing_state.rules_cache_id,
            ruleset_compatible=existing_state.ruleset_compatible,
        )

        self._apply_ruleset_compatibility(compatible_state, settings.get_rules_path().strip())

        dialog = QMessageBox(self)
        dialog.setWindowTitle("capa explorer")
        dialog.setText(f"This database contains capa results generated on {self._analysis_timestamp_text(compatible_state)}.")
        if compatible_state.ruleset_compatible:
            dialog.setIcon(QMessageBox.Question)
            dialog.setInformativeText("Load existing data or analyze program again?")
        else:
            dialog.setIcon(QMessageBox.Warning)
            dialog.setInformativeText(
                "The cached results were generated with a different capa ruleset than the one currently configured.\n"
                "Load existing data anyway or analyze program again?"
            )

        load_button = dialog.addButton("Load existing results", QMessageBox.AcceptRole)
        reanalyze_button = dialog.addButton("Reanalyze program", QMessageBox.ActionRole)
        dialog.addButton(QMessageBox.Cancel)
        dialog.setDefaultButton(reanalyze_button if not compatible_state.ruleset_compatible else load_button)
        dialog.exec()

        clicked = dialog.clickedButton()
        if clicked is load_button:
            self._load_existing_program_analysis(compatible_state)
            return "load"
        if clicked is reanalyze_button:
            return "reanalyze"
        return "cancel"

    def _show_analysis_progress_dialog(
        self,
        text: str,
        current: Optional[int] = None,
        total: Optional[int] = None,
    ) -> None:
        if not self._is_alive():
            return

        dialog = self._analysis_progress_dialog
        if dialog is None:
            dialog = QProgressDialog(self)
            dialog.setWindowTitle("capa explorer")
            dialog.setWindowModality(Qt.WindowModal)
            dialog.setMinimumDuration(0)
            dialog.setRange(0, 0)
            dialog.setCancelButtonText("Cancel")
            dialog.setAutoClose(False)
            dialog.setAutoReset(False)
            dialog.canceled.connect(self._cancel_analysis)
            self._analysis_progress_dialog = dialog

        dialog.setLabelText(text)
        if current is None or total is None or total <= 0:
            dialog.setRange(0, 0)
        else:
            dialog.setRange(0, total)
            dialog.setValue(max(0, min(current, total)))
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def _close_analysis_progress_dialog(self) -> None:
        dialog = self._analysis_progress_dialog
        if dialog is None:
            return

        self._analysis_progress_dialog = None
        try:
            dialog.blockSignals(True)
            dialog.hide()
            dialog.close()
            dialog.deleteLater()
        except RuntimeError:
            pass

    def _cancel_analysis(self) -> None:
        if not self._analysis_running:
            return
        if self._analysis_task is not None:
            self._analysis_task.cancelled = True
        self._set_status("Cancelling Program Analysis...")
        self._show_analysis_progress_dialog("Cancelling capa analysis...")

    def _refresh_current_offset_from_ui(self) -> None:
        if self.bv is None:
            return

        try:
            context = UIContext.activeContext()
            view_frame = context.getCurrentViewFrame() if context else None
            if view_frame is None:
                return

            current_bv = _coerce_binary_view(view_frame.getCurrentBinaryView())
            if current_bv is not self.bv:
                return

            offset = int(view_frame.getCurrentOffset())
        except Exception:
            return

        self.current_offset = offset
        self._hooks.offset = offset
        self._hooks.function_start = self._get_function_start(offset)

    def _current_function_start(self) -> Optional[int]:
        self._refresh_current_offset_from_ui()
        return self._hooks.function_start

    def _current_function_name(self) -> Optional[str]:
        if self.bv is None:
            return None

        function_start = self._current_function_start()
        if function_start is None:
            return None

        try:
            functions = self.bv.get_functions_containing(function_start)
        except Exception:
            return None

        if not functions:
            return None

        return functions[0].name

    def _get_function_start(self, address: int) -> Optional[int]:
        if self.bv is None:
            return None

        try:
            functions = self.bv.get_functions_containing(address)
        except Exception:
            return None

        if not functions:
            return None

        return int(functions[0].start)

    def _get_function_name_for_address(self, address: int) -> str:
        if self.bv is None:
            return f"sub_{address:X}"

        try:
            functions = self.bv.get_functions_containing(address)
        except Exception:
            functions = []

        if functions:
            return functions[0].name

        return f"sub_{address:X}"

    def _clear_current_analysis_results(self, *, clear_persisted: bool) -> None:
        rules_path = settings.get_rules_path().strip()

        if self.bv is not None and rules_path:
            _analysis_cache.clear(self.bv, rules_path)

        if clear_persisted and self.bv is not None:
            try:
                self.bv.remove_metadata(ANALYSIS_METADATA_KEY)
            except KeyError:
                pass
            except Exception:
                logger.exception("[%s] failed to remove persisted analysis metadata", PLUGIN_NAME)

        self._analysis_state = None
        self._clear_program_tree_selections()
        self._load_program_analysis_placeholder()

    def _refresh_from_database_change(self, reason: str, bv: Optional[bn.BinaryView]) -> None:
        self._database_refresh_pending = False
        if not self._is_alive():
            return

        changed_bv = _coerce_binary_view(bv)
        if changed_bv is not None and self.bv is not None and changed_bv is not self.bv:
            if reason == "rebased" and _bv_path(changed_bv) and _bv_path(changed_bv) == _bv_path(self.bv):
                self._sync_view_state(changed_bv, reset_offset=True)
            else:
                return

        if reason == "rebased":
            logger.info("[%s] BinaryView rebased, clearing cached capa results", PLUGIN_NAME)
            self._clear_current_analysis_results(clear_persisted=True)
            self._set_status("BinaryView rebased. Re-run capa analysis.")
            return

        if self._analysis_state is not None:
            self._render_current_program_analysis()
            self._set_status(self._analysis_summary_text(self._analysis_state))

    def _queue_deferred_database_refresh(self, reason: str, bv: Optional[bn.BinaryView]) -> None:
        # Coalesce BinaryView notifications while Qt tree updates or highlight writes are in flight.
        if self._deferred_database_refresh is None or self._deferred_database_refresh[0] != "rebased" or reason == "rebased":
            self._deferred_database_refresh = (reason, bv)

        if self._deferred_database_refresh_scheduled:
            return

        self._deferred_database_refresh_scheduled = True
        QtCore.QTimer.singleShot(0, self._flush_deferred_database_refresh)

    def _flush_deferred_database_refresh(self) -> None:
        self._deferred_database_refresh_scheduled = False
        if not self._is_alive():
            self._deferred_database_refresh = None
            return

        if self.program_tree.is_updating():
            if not self._deferred_database_refresh_scheduled:
                self._deferred_database_refresh_scheduled = True
                QtCore.QTimer.singleShot(0, self._flush_deferred_database_refresh)
            return

        deferred = self._deferred_database_refresh
        self._deferred_database_refresh = None
        if deferred is None:
            return

        reason, bv = deferred
        self._refresh_from_database_change(reason, bv)

    def _on_binary_view_database_changed(self, reason: str, bv: Optional[bn.BinaryView]) -> None:
        if reason == "function_updated" and self._suspend_function_update_refresh:
            return

        if self.program_tree.is_updating():
            self._queue_deferred_database_refresh(reason, bv)
            return

        if self._database_refresh_pending and reason != "rebased":
            return

        self._database_refresh_pending = True
        self._refresh_from_database_change(reason, bv)

    def notifyViewChanged(self, view_frame):
        if not self._is_alive():
            return

        try:
            self._hooks.handle_view_changed(view_frame)
            self._sync_view_state(self._hooks.bv, reset_offset=True)
            logger.debug(
                "[%s] widget id=%s view changed to %s",
                PLUGIN_NAME,
                self._instance_id,
                _bv_path(self.bv) or "<no file>",
            )
        except Exception:
            logger.exception("[%s] notifyViewChanged failed", PLUGIN_NAME)

    def notifyOffsetChanged(self, offset):
        if not self._is_alive():
            return

        try:
            function_changed = self._hooks.handle_offset_changed(offset)
            self.bv = _coerce_binary_view(self._hooks.bv)
            self.current_offset = self._hooks.offset

            if function_changed and self.cb_limit_results_by_function.isChecked() and self._analysis_state is not None:
                self._render_current_program_analysis()
        except Exception:
            logger.exception("[%s] notifyOffsetChanged failed", PLUGIN_NAME)

    def _on_analyze_clicked(self) -> None:
        action = self._prompt_for_existing_program_analysis()
        if action != "reanalyze":
            return

        self._start_program_analysis()

    def _on_reset_clicked(self) -> None:
        self.cb_limit_results_by_function.setChecked(False)
        self.cb_show_matches_by_function.setChecked(False)
        self.search_bar.clear()
        self._clear_program_tree_selections()

        if self._analysis_state is not None:
            self._render_current_program_analysis()
        else:
            self._load_program_analysis_placeholder()

        self._set_status(DEFAULT_STATUS)

    def _on_settings_clicked(self) -> None:
        dialog = CapaSettingsDialog(self)
        if dialog.exec():
            settings.set_rules_path(dialog.value())
            self._restore_cached_results()
            self._set_status("Updated capa explorer settings.")

    def _on_save_clicked(self) -> None:
        if self._analysis_state is None:
            self._set_status("No program analysis available to save.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save capa analysis",
            "capa-analysis.json",
            "JSON Files (*.json);;All Files (*)",
        )
        if not path:
            return

        doc = self._analysis_state.doc
        doc_path = Path(path)
        doc_path.write_text(doc.model_dump_json(indent=2), encoding="utf-8")
        self._set_status(f"Saved program analysis to {doc_path}.")

    def _ensure_rules_path(self) -> Optional[str]:
        rules_path = settings.get_rules_path().strip()
        error_message = _rules_path_error(rules_path)
        if error_message is None:
            return rules_path

        while True:
            self._set_status(error_message or "Select a local capa rules directory before running analysis.")
            dialog = CapaSettingsDialog(self)
            if not dialog.exec():
                return None

            rules_path = dialog.value()
            settings.set_rules_path(rules_path)

            error_message = _rules_path_error(rules_path)
            if error_message is None:
                return rules_path

            QMessageBox.warning(self, "capa explorer", error_message)

    def _start_program_analysis(self) -> None:
        if self.bv is None:
            self._set_status("Open a binary before running Program Analysis.")
            return

        if self._analysis_running:
            self._set_status("Program Analysis is already running.")
            self._show_analysis_progress_dialog("Analyzing current Binary Ninja view...")
            return

        rules_path = self._ensure_rules_path()
        if not rules_path:
            return

        if not is_capa_available():
            message = get_capa_import_error_message()
            self._set_status(message)
            bn.log_error(f"[{PLUGIN_NAME}] {message}")
            return

        self._analysis_running = True
        self._analysis_task_token += 1
        task_token = self._analysis_task_token
        current_bv = self.bv
        sample_path = _bv_path(current_bv)
        self.btn_analyze.setEnabled(False)
        self._show_analysis_progress_dialog("Loading capa rules and analyzing the current Binary Ninja view...")
        self._set_status("Loading capa rules and analyzing the current Binary Ninja view...")
        logger.info("[%s] starting analysis for %s", PLUGIN_NAME, sample_path or "<no path>")

        def progress(message: str, current: Optional[int] = None, total: Optional[int] = None) -> None:
            bn.mainthread.execute_on_main_thread(
                lambda: self._update_analysis_progress_dialog(task_token, message, current, total)
            )

        def work(task: _Task):
            def should_cancel() -> bool:
                return task.cancelled or task_token != self._analysis_task_token or not self._is_alive()

            def progress_with_task(message: str, current: Optional[int] = None, total: Optional[int] = None) -> None:
                task.progress = f"capa: {message}"
                progress(message, current, total)

            return self._run_program_analysis(current_bv, rules_path, sample_path, progress_with_task, should_cancel)

        def done(result, error):
            self._analysis_running = False
            self._analysis_task = None

            if task_token != self._analysis_task_token or not self._is_alive():
                return

            self.btn_analyze.setEnabled(True)
            self._close_analysis_progress_dialog()

            if error:
                if isinstance(error, AnalysisCancelledError):
                    self._set_status("Program Analysis cancelled.")
                    logger.info("[%s] analysis cancelled by user", PLUGIN_NAME)
                    return

                error_message = f"{type(error).__name__}: {error}"
                self._set_status(f"Program Analysis failed: {error_message}")
                bn.log_error(f"[{PLUGIN_NAME}] {error_message}")
                return

            assert result is not None
            state = ProgramAnalysisState(
                doc=result["doc"],
                rules_path=result["rules_path"],
                rules_count=result["rules_count"],
                limitation_found=result["limitation_found"],
                from_cache=False,
                rules_cache_id=str(result.get("rules_cache_id", "")),
                ruleset_compatible=True,
            )
            self._analysis_state = state
            _analysis_cache.put(current_bv, rules_path, state)
            self._persist_analysis_state(current_bv, state)
            self._render_current_program_analysis()
            self._set_status(self._analysis_summary_text(state))

        task = _Task("capa: analyzing current Binary Ninja view...", work, done)
        self._analysis_task = task
        task.start()

    def _update_analysis_progress_dialog(
        self,
        task_token: int,
        message: str,
        current: Optional[int] = None,
        total: Optional[int] = None,
    ) -> None:
        if task_token != self._analysis_task_token or not self._analysis_running:
            return
        self._show_analysis_progress_dialog(f"capa explorer...\n{message}", current, total)

    def _run_program_analysis(
        self,
        bv: bn.BinaryView,
        rules_path: str,
        sample_path: str,
        progress=None,
        should_cancel=None,
    ) -> dict[str, object]:
        logger.debug("[%s] running program analysis via extractor helper", PLUGIN_NAME)
        return run_program_analysis(
            bv,
            rules_path,
            sample_path,
            progress_callback=progress,
            should_cancel=should_cancel,
        )

    def _render_current_program_analysis(self) -> None:
        if self._analysis_state is None:
            self._load_program_analysis_placeholder()
            return

        self._update_range_proxy()
        self._clear_instruction_highlights()
        self.program_tree.load_results(
            self._analysis_state.doc,
            bv=self.bv,
            group_by_function=self.cb_show_matches_by_function.isChecked(),
            include_location=lambda location: (
                (not self.cb_limit_results_by_function.isChecked()) or self._filter_match_for_current_function(location)
            ),
            get_function_start=self._get_function_start,
            get_function_name=self._get_function_name_for_address,
            address_display_parts=self._address_display_parts,
        )
        self.program_tree.apply_text_filter(self.search_bar.text())

    def _update_range_proxy(self) -> None:
        if not self.cb_limit_results_by_function.isChecked():
            self._range_proxy.reset_address_range()
            return

        function_start = self._current_function_start()
        if function_start is None or self.bv is None:
            self._range_proxy.reset_address_range()
            return

        try:
            functions = self.bv.get_functions_containing(function_start)
        except Exception:
            self._range_proxy.reset_address_range()
            return

        if not functions:
            self._range_proxy.reset_address_range()
            return

        function = functions[0]
        self._range_proxy.set_address_range(int(function.start), int(function.highest_address) + 1)

    def _filter_match_for_current_function(self, location) -> bool:
        return self._range_proxy.accepts_location(location)

    def _resolve_highlight_target(self, address_value: Optional[int], address_kind: Optional[str]) -> Optional[tuple[object, int]]:
        if self.bv is None or address_value is None:
            return None

        target = int(address_value)
        if address_kind == "file-offset":
            try:
                resolved = self.bv.get_address_for_data_offset(target)
            except Exception:
                return None
            if resolved is None:
                return None
            target = int(resolved)

        try:
            functions = self.bv.get_functions_containing(target)
        except Exception:
            return None

        if not functions:
            return None

        return functions[0], target

    def _set_instruction_highlight(self, address_value: Optional[int], address_kind: Optional[str], enabled: bool) -> None:
        resolved = self._resolve_highlight_target(address_value, address_kind)
        if resolved is None:
            return

        function, target = resolved
        key = (int(function.start), int(target))

        try:
            self._suspend_function_update_refresh += 1
            if enabled:
                state = self._program_highlight_state.get(key)
                if state is not None:
                    state["count"] = int(state["count"]) + 1
                    return

                previous = function.get_instr_highlight(target)
                self._program_highlight_state[key] = {"previous": previous, "count": 1}
                function.set_user_instr_highlight(target, bn.HighlightStandardColor.YellowHighlightColor)
                return

            state = self._program_highlight_state.get(key)
            if state is None:
                return

            remaining = int(state["count"]) - 1
            if remaining > 0:
                state["count"] = remaining
                return

            function.set_user_instr_highlight(target, state["previous"])
            del self._program_highlight_state[key]
        except Exception:
            logger.exception("[%s] failed to update instruction highlight", PLUGIN_NAME)
        finally:
            self._suspend_function_update_refresh = max(0, self._suspend_function_update_refresh - 1)

    def _clear_instruction_highlights(self, bv: Optional[bn.BinaryView] = None) -> None:
        target_bv = _coerce_binary_view(bv) or self.bv

        try:
            self._suspend_function_update_refresh += 1
            if target_bv is not None:
                for (function_start, target), state in list(self._program_highlight_state.items()):
                    try:
                        functions = target_bv.get_functions_containing(function_start) or target_bv.get_functions_containing(target)
                        if not functions:
                            continue
                        functions[0].set_user_instr_highlight(target, state["previous"])
                    except Exception:
                        logger.exception("[%s] failed to clear instruction highlight", PLUGIN_NAME)
        finally:
            self._suspend_function_update_refresh = max(0, self._suspend_function_update_refresh - 1)

        self._program_highlight_state.clear()

    def _clear_program_tree_selections(self) -> None:
        self._clear_instruction_highlights()
        self.program_tree.clear_selections()

    def _address_display_parts(self, location) -> tuple[str, str, Optional[int], Optional[str]]:
        from capa.features.address import (
            AbsoluteVirtualAddress,
            FileOffsetAddress,
            NO_ADDRESS,
        )

        if location is None or location is NO_ADDRESS:
            return "", "", None, None
        if isinstance(location, AbsoluteVirtualAddress):
            return f"0x{int(location):X}", "absolute", int(location), "absolute"
        if isinstance(location, FileOffsetAddress):
            return f"file+0x{int(location):X}", "file offset", int(location), "file-offset"
        if isinstance(location, int):
            return f"0x{int(location):X}", "absolute", int(location), "absolute"
        return str(location), "", None, None

    def _on_search_changed(self, text: str) -> None:
        self.program_tree.apply_text_filter(text)
        if text:
            self._set_status(f"Filtering Program Analysis results for {text!r}.")
        elif self._analysis_state is not None:
            self._set_status(self._analysis_summary_text(self._analysis_state))
        else:
            self._set_status(DEFAULT_STATUS)

    def _on_limit_results_by_function_changed(self, state: int) -> None:
        if self._analysis_state is not None:
            self._render_current_program_analysis()

        if state == Qt.Checked:
            function_name = self._current_function_name()
            if function_name:
                self._set_status(f"Limiting Program Analysis to {function_name}.")
            else:
                self._set_status("Current-function filtering is enabled, but no active function is selected.")
        elif self._analysis_state is not None:
            self._set_status(self._analysis_summary_text(self._analysis_state))
        else:
            self._set_status(DEFAULT_STATUS)

    def _on_show_matches_by_function_changed(self, state: int) -> None:
        del state
        if self._analysis_state is not None:
            self._render_current_program_analysis()
            self._set_status(self._analysis_summary_text(self._analysis_state))
        else:
            self._set_status(DEFAULT_STATUS)

    def _rename_program_analysis_function(self, address_value: Optional[int]) -> None:
        if self.bv is None or address_value is None:
            return

        function_start = self._get_function_start(int(address_value)) or int(address_value)

        try:
            functions = self.bv.get_functions_containing(function_start)
        except Exception:
            functions = []

        if not functions:
            self._set_status(f"No function found at 0x{function_start:X}.")
            return

        function = functions[0]
        current_name = function.name or f"sub_{function_start:X}"

        try:
            new_name = bn.get_text_line_input(f"Rename function ({current_name})", "capa explorer")
        except Exception as error:
            logger.exception("[%s] failed to open rename prompt", PLUGIN_NAME)
            bn.log_error(f"[{PLUGIN_NAME}] failed to open rename prompt: {error}")
            return

        if new_name is None:
            return

        if isinstance(new_name, bytes):
            new_name = new_name.decode("utf-8", errors="ignore")

        new_name = str(new_name).strip()
        if not new_name:
            self._set_status("Function rename cancelled: empty name.")
            return

        if new_name == current_name:
            return

        try:
            function.name = new_name
        except Exception as error:
            logger.exception("[%s] failed to rename function 0x%X", PLUGIN_NAME, function_start)
            bn.log_error(f"[{PLUGIN_NAME}] failed to rename function: {error}")
            self._set_status(f"Failed to rename function at 0x{function_start:X}.")
            return

        if self._analysis_state is not None:
            self._render_current_program_analysis()

        self._set_status(f"Renamed function 0x{function_start:X} to {new_name}.")

    def _navigate_program_analysis_address(self, address_value: Optional[int], address_kind: Optional[str]) -> None:
        if self.bv is None or address_value is None or address_kind is None:
            return

        try:
            target = int(address_value)
            if address_kind == "file-offset":
                target = self.bv.get_address_for_data_offset(target) or target

            context = UIContext.activeContext()
            view_frame = context.getCurrentViewFrame() if context else None
            if view_frame is not None:
                view_frame.navigate(self.bv, target)
                self._set_status(f"Navigated to 0x{int(target):X}.")
        except Exception as error:
            logger.exception("[%s] failed to navigate", PLUGIN_NAME)
            bn.log_error(f"[{PLUGIN_NAME}] failed to navigate: {error}")


class CapaExplorerSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        super().__init__(_load_icon_image(), PLUGIN_NAME)

    def createWidget(self, frame, data):
        return CapaExplorerSidebarWidget(PLUGIN_NAME, frame, data)

    def defaultLocation(self):
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        return SidebarContextSensitivity.SelfManagedSidebarContext
