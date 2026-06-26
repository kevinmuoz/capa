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

from typing import Iterable, Optional


class CapaExplorerRangeProxy:
    """Filter matches by a currently selected address range."""

    def __init__(self) -> None:
        self.min_addr: Optional[int] = None
        self.max_addr: Optional[int] = None

    def set_address_range(self, min_addr: int, max_addr: int) -> None:
        self.min_addr = min_addr
        self.max_addr = max_addr

    def reset_address_range(self) -> None:
        self.min_addr = None
        self.max_addr = None

    def accepts_location(self, location) -> bool:
        if self.min_addr is None or self.max_addr is None:
            return True

        if isinstance(location, int):
            value = int(location)
            return self.min_addr <= value < self.max_addr

        return False


class CapaExplorerSearchProxy:
    """Filter rows using a simple substring search across displayed columns."""

    def __init__(self) -> None:
        self.query = ""

    def set_query(self, query: str) -> None:
        self.query = query.lower().strip()

    def reset_query(self) -> None:
        self.query = ""

    def accepts_columns(self, columns: Iterable[str]) -> bool:
        if not self.query:
            return True

        for column in columns:
            if self.query in (column or "").lower():
                return True

        return False
