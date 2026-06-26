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

import logging
from typing import Optional

import binaryninja as bn
from binaryninjaui import (
    Menu,
    UIAction,
    UIActionContext,
    UIActionHandler,
    UIContext,
    UIContextNotification,
    View,
)

from .capa_sidebar_widget import PLUGIN_NAME, open_capa_sidebar

logger = logging.getLogger("capa.binja")


class FlareAction:
    MENU_GROUP = PLUGIN_NAME

    def __init__(self, name: str, description: str, priority: int) -> None:
        self.name = name
        self.description = description
        self.priority = priority

    @property
    def full_name(self) -> str:
        return f"{self.MENU_GROUP}\\{self.name}"


class FlareActions:
    OPEN_CAPA_EXPLORER = FlareAction(
        name="Open capa explorer",
        description="Open the FLARE capa explorer sidebar",
        priority=0,
    )


class FlareActionHandlers:
    @staticmethod
    def execute_open_capa_explorer(ctx: UIActionContext) -> None:
        del ctx

        def open_sidebar() -> None:
            if not open_capa_sidebar():
                bn.log_warn(f"[{PLUGIN_NAME}] unable to open sidebar from context menu")

        bn.mainthread.execute_on_main_thread(open_sidebar)

    @staticmethod
    def is_open_capa_explorer_available(ctx: UIActionContext) -> bool:
        return getattr(ctx, "binaryView", None) is not None


class FlareCapaContextMenuNotification(UIContextNotification):
    def OnContextMenuCreated(self, context: UIContext, view: View, menu: Menu) -> None:
        del context
        del view

        if menu is None:
            return

        action = FlareActions.OPEN_CAPA_EXPLORER
        try:
            existing_actions = menu.getActions()
            if action.full_name in existing_actions:
                menu.removeAction(action.full_name)
            menu.addAction(action.full_name, action.MENU_GROUP, action.priority)
        except Exception as error:
            logger.debug("failed to inject capa context menu action: %s", error)


_notification_instance: Optional[FlareCapaContextMenuNotification] = None
_ui_action_registered = False


def _register_ui_actions() -> None:
    global _ui_action_registered

    if _ui_action_registered:
        return

    handler = UIActionHandler.globalActions()
    action = FlareActions.OPEN_CAPA_EXPLORER

    if not UIAction.isActionRegistered(action.full_name):
        UIAction.registerAction(action.full_name)

    handler.bindAction(
        action.full_name,
        UIAction(
            FlareActionHandlers.execute_open_capa_explorer,
            FlareActionHandlers.is_open_capa_explorer_available,
        ),
    )

    _ui_action_registered = True


def register_context_menu() -> None:
    global _notification_instance

    _register_ui_actions()

    if _notification_instance is not None:
        return

    _notification_instance = FlareCapaContextMenuNotification()
    bn.mainthread.execute_on_main_thread(lambda: UIContext.registerNotification(_notification_instance))
