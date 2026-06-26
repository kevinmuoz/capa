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


class ProgramAnalysisState:
    def __init__(
        self,
        doc: object,
        rules_path: str,
        rules_count: int,
        limitation_found: bool = False,
        from_cache: bool = False,
        rules_cache_id: str = "",
        ruleset_compatible: bool = True,
    ) -> None:
        self.doc = doc
        self.rules_path = rules_path
        self.rules_count = rules_count
        self.limitation_found = limitation_found
        self.from_cache = from_cache
        self.rules_cache_id = rules_cache_id
        self.ruleset_compatible = ruleset_compatible


class CapaExplorerResultCache:
    def __init__(self) -> None:
        self._cache: dict[tuple[str, str], ProgramAnalysisState] = {}

    def _key(self, bv: Optional[bn.BinaryView], rules_path: str) -> tuple[str, str]:
        return (f"bv:{id(bv)}", rules_path)

    def get(self, bv: Optional[bn.BinaryView], rules_path: str) -> Optional[ProgramAnalysisState]:
        return self._cache.get(self._key(bv, rules_path))

    def put(self, bv: Optional[bn.BinaryView], rules_path: str, state: ProgramAnalysisState) -> None:
        self._cache[self._key(bv, rules_path)] = state

    def clear(self, bv: Optional[bn.BinaryView], rules_path: str) -> None:
        self._cache.pop(self._key(bv, rules_path), None)
