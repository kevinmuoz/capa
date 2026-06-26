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

from typing import Callable, Optional

import binaryninja as bn


class CapaExplorerBinjaDataNotification(bn.BinaryDataNotification):
    def __init__(self, callback: Callable[[str, Optional[bn.BinaryView]], None]) -> None:
        super().__init__()
        self._callback = callback

    def _notify(self, reason: str, bv: Optional[bn.BinaryView]) -> None:
        try:
            bn.mainthread.execute_on_main_thread(lambda: self._callback(reason, bv))
        except Exception:
            pass

    def function_updated(self, view: bn.BinaryView, func) -> None:
        del func
        self._notify("function_updated", view)

    def symbol_added(self, view: bn.BinaryView, sym) -> None:
        del sym
        self._notify("symbol_added", view)

    def symbol_removed(self, view: bn.BinaryView, sym) -> None:
        del sym
        self._notify("symbol_removed", view)

    def symbol_updated(self, view: bn.BinaryView, sym) -> None:
        del sym
        self._notify("symbol_updated", view)

    def rebased(self, old_view: bn.BinaryView, new_view: bn.BinaryView) -> None:
        del old_view
        self._notify("rebased", new_view)


class CapaExplorerBinjaHooks:
    """Small state helper mirroring the responsibility of the IDA hooks module."""

    def __init__(self, database_changed_callback: Optional[Callable[[str, Optional[bn.BinaryView]], None]] = None) -> None:
        self.bv: Optional[bn.BinaryView] = None
        self.offset: Optional[int] = None
        self.function_start: Optional[int] = None
        self._notification: Optional[CapaExplorerBinjaDataNotification] = None
        self._registered_bv: Optional[bn.BinaryView] = None
        self._database_changed_callback = database_changed_callback

        if database_changed_callback is not None:
            self._notification = CapaExplorerBinjaDataNotification(database_changed_callback)

    def close(self) -> None:
        self._set_notification_view(None)
        self.bv = None
        self.offset = None
        self.function_start = None

    def set_binary_view(self, bv: Optional[bn.BinaryView]) -> None:
        self.bv = bv
        self._set_notification_view(bv)

    def _set_notification_view(self, bv: Optional[bn.BinaryView]) -> None:
        if self._notification is None or self._registered_bv is bv:
            return

        if self._registered_bv is not None:
            try:
                self._registered_bv.unregister_notification(self._notification)
            except Exception:
                pass

        self._registered_bv = bv
        if self._registered_bv is not None:
            try:
                self._registered_bv.register_notification(self._notification)
            except Exception:
                self._registered_bv = None

    def handle_view_changed(self, view_frame) -> bool:
        try:
            self.set_binary_view(view_frame.getCurrentBinaryView() if view_frame else None)
        except Exception:
            self.set_binary_view(None)

        self.offset = None
        self.function_start = None
        return True

    def handle_offset_changed(self, offset) -> bool:
        previous = self.function_start

        try:
            self.offset = int(offset) if offset is not None else None
        except Exception:
            self.offset = None

        self.function_start = self._resolve_function_start(self.bv, self.offset)
        return previous != self.function_start

    @staticmethod
    def _resolve_function_start(bv: Optional[bn.BinaryView], offset: Optional[int]) -> Optional[int]:
        if bv is None or offset is None:
            return None

        try:
            functions = bv.get_functions_containing(offset)
        except Exception:
            return None

        if not functions:
            return None

        return int(functions[0].start)
