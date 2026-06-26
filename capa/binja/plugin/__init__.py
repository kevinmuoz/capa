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

import os
import logging
import traceback
from pathlib import Path

import binaryninja as bn
from binaryninjaui import Sidebar

from .capa_sidebar_widget import CapaExplorerSidebarWidgetType, PLUGIN_NAME
from .context_menu import register_context_menu

_plugin_initialized = False
_sidebar_widget_type = None
_logging_configured = False
LOGGER_NAME = "capa.binja"
DEBUG_ENV_VAR = "CAPA_BINJA_DEBUG"
LOG_PATH_ENV_VAR = "CAPA_BINJA_LOG_PATH"


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def setup_logging() -> None:
    global _logging_configured

    if _logging_configured:
        return

    debug_enabled = _env_flag(DEBUG_ENV_VAR)
    log_path_value = os.environ.get(LOG_PATH_ENV_VAR, "").strip()
    if not debug_enabled and not log_path_value:
        _logging_configured = True
        return

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")

    if debug_enabled:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    log_path = None
    if log_path_value:
        log_path = Path(log_path_value).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    _logging_configured = True
    if log_path is not None:
        bn.log_info(f"[{PLUGIN_NAME}] debug logging enabled: {log_path}")
    elif debug_enabled:
        bn.log_info(f"[{PLUGIN_NAME}] debug logging enabled via {DEBUG_ENV_VAR}")


def init_plugin() -> bool:
    global _plugin_initialized
    global _sidebar_widget_type

    if _plugin_initialized:
        return True

    try:
        setup_logging()
        register_context_menu()

        _sidebar_widget_type = CapaExplorerSidebarWidgetType()
        Sidebar.addSidebarWidgetType(_sidebar_widget_type)

        _plugin_initialized = True
        bn.log_info(f"[{PLUGIN_NAME}] sidebar widget type registered")
        return True
    except Exception:
        bn.log_error(f"[{PLUGIN_NAME}] initialization failed:\n{traceback.format_exc()}")
        return False


init_plugin()
