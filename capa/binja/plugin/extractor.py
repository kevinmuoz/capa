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

import importlib
import sys
from pathlib import Path
from typing import Callable, Optional

import binaryninja as bn

ProgressCallback = Callable[[str, Optional[int], Optional[int]], None]
CancelCallback = Callable[[], bool]


class AnalysisCancelledError(RuntimeError):
    pass


def _import_capa_runtime() -> None:
    importlib.import_module("capa.loader")
    importlib.import_module("capa.rules")
    importlib.import_module("capa.rules.cache")
    importlib.import_module("capa.features.extractors.binja.extractor")


def is_capa_available() -> bool:
    try:
        _import_capa_runtime()
        return True
    except Exception:
        return False


def get_capa_import_error_message(error: Exception | None = None) -> str:
    base = (
        "The Python package 'flare-capa' is not usable in Binary Ninja's Python environment. "
        f"Binary Ninja is running Python {sys.version_info.major}.{sys.version_info.minor} at {sys.executable}."
    )

    if isinstance(error, ModuleNotFoundError):
        missing = error.name or str(error)
        if missing in {"msgspec._core", "pydantic_core._pydantic_core", "msgpack._cmsgpack", "_yaml"}:
            return (
                f"{base} Missing compiled module '{missing}'. "
                "This usually means flare-capa was installed with a different Python version/ABI than Binary Ninja. "
                "Reinstall flare-capa using Binary Ninja's own Python interpreter, not the system python."
            )

        return f"{base} Missing module '{missing}'. Reinstall flare-capa into Binary Ninja's Python environment."

    if error is not None:
        return f"{base} Import failed: {type(error).__name__}: {error}"

    return (
        f"{base} Install it for the Binary Ninja interpreter or load the plugin from an environment "
        "where 'capa' and its compiled dependencies are importable."
    )


def _report_progress(
    progress_callback: Optional[ProgressCallback],
    message: str,
    current: Optional[int] = None,
    total: Optional[int] = None,
) -> None:
    if progress_callback is not None:
        progress_callback(message, current, total)


def _raise_if_cancelled(should_cancel: Optional[CancelCallback]) -> None:
    if should_cancel is not None and should_cancel():
        raise AnalysisCancelledError("Program Analysis cancelled.")


def _create_cancellable_binja_extractor(
    bextractor,
    bv: bn.BinaryView,
    should_cancel: Optional[CancelCallback] = None,
    progress_callback: Optional[ProgressCallback] = None,
):
    class CancellableBinjaFeatureExtractor(bextractor.BinjaFeatureExtractor):
        def __init__(self, binary_view: bn.BinaryView):
            super().__init__(binary_view)
            self._should_cancel = should_cancel
            self._progress_callback = progress_callback
            self._function_progress_total: Optional[int] = None
            self._function_progress_count = 0

        def _raise_if_cancelled(self) -> None:
            _raise_if_cancelled(self._should_cancel)

        def set_function_progress_total(self, total: int) -> None:
            self._function_progress_total = total
            self._function_progress_count = 0

        def _report_function_progress(self, function_handle) -> None:
            if self._function_progress_total is None:
                return

            function_address = int(function_handle.address)
            _report_progress(
                self._progress_callback,
                f"extracting features from function at 0x{function_address:X}",
                self._function_progress_count + 1,
                self._function_progress_total,
            )
            self._function_progress_count += 1

        def extract_global_features(self):
            self._raise_if_cancelled()
            yield from super().extract_global_features()

        def extract_file_features(self):
            self._raise_if_cancelled()
            yield from super().extract_file_features()

        def get_functions(self):
            self._raise_if_cancelled()
            for function in super().get_functions():
                self._raise_if_cancelled()
                yield function

        def extract_function_features(self, function_handle):
            self._raise_if_cancelled()
            self._report_function_progress(function_handle)
            for feature in super().extract_function_features(function_handle):
                self._raise_if_cancelled()
                yield feature

        def get_basic_blocks(self, function_handle):
            self._raise_if_cancelled()
            for basic_block in super().get_basic_blocks(function_handle):
                self._raise_if_cancelled()
                yield basic_block

        def extract_basic_block_features(self, function_handle, basic_block_handle):
            self._raise_if_cancelled()
            for feature in super().extract_basic_block_features(function_handle, basic_block_handle):
                self._raise_if_cancelled()
                yield feature

        def get_instructions(self, function_handle, basic_block_handle):
            self._raise_if_cancelled()
            for instruction in super().get_instructions(function_handle, basic_block_handle):
                self._raise_if_cancelled()
                yield instruction

        def extract_insn_features(self, function_handle, basic_block_handle, instruction_handle):
            self._raise_if_cancelled()
            for feature in super().extract_insn_features(function_handle, basic_block_handle, instruction_handle):
                self._raise_if_cancelled()
                yield feature

        def is_library_function(self, addr):
            self._raise_if_cancelled()
            return super().is_library_function(addr)

        def get_function_name(self, addr):
            self._raise_if_cancelled()
            return super().get_function_name(addr)

    return CancellableBinjaFeatureExtractor(bv)


def _load_rules(
    rules_path: str,
    progress_callback: Optional[ProgressCallback] = None,
    should_cancel: Optional[CancelCallback] = None,
) -> tuple[object, Path, int, str]:
    import capa.rules
    import capa.rules.cache

    rules_root = Path(rules_path)
    _report_progress(progress_callback, "loading capa rules")
    _raise_if_cancelled(should_cancel)

    def on_load_rule(_path, i: int, total: int) -> None:
        _raise_if_cancelled(should_cancel)
        _report_progress(progress_callback, f"loading capa rules ({i + 1} of {total})", i + 1, total)

    rules = capa.rules.get_rules([rules_root], on_load_rule=on_load_rule)
    rules_count = getattr(rules, "source_rule_count", len(getattr(rules, "rules", {})))
    rules_cache_id = str(capa.rules.cache.compute_ruleset_cache_identifier(rules))
    return rules, rules_root, rules_count, rules_cache_id


def get_rules_cache_metadata(
    rules_path: str,
    progress_callback: Optional[ProgressCallback] = None,
    should_cancel: Optional[CancelCallback] = None,
) -> dict[str, object]:
    try:
        _import_capa_runtime()
    except Exception as error:
        raise RuntimeError(get_capa_import_error_message(error)) from error

    rules, _, rules_count, rules_cache_id = _load_rules(rules_path, progress_callback, should_cancel)
    del rules
    return {
        "rules_count": rules_count,
        "rules_cache_id": rules_cache_id,
    }


def validate_analysis_document_for_view(bv: bn.BinaryView, doc: object) -> bool:
    import capa.render.utils as rutils
    from capa.features.address import AbsoluteVirtualAddress

    for rule in rutils.capability_rules(doc):
        for location_, _ in rule.matches:
            location = location_.to_capa()
            if not isinstance(location, AbsoluteVirtualAddress):
                continue

            address = int(location)
            try:
                if bv.get_segment_at(address) is None:
                    return False
            except Exception:
                return False

    return True


def run_program_analysis(
    bv: bn.BinaryView,
    rules_path: str,
    sample_path: str,
    progress_callback: Optional[ProgressCallback] = None,
    should_cancel: Optional[CancelCallback] = None,
) -> dict[str, object]:
    try:
        _import_capa_runtime()
        import capa.loader
        import capa.features.common
        import capa.capabilities.common as ccommon
        import capa.render.result_document as rd
        import capa.features.extractors.binja.extractor as bextractor
    except Exception as error:
        raise RuntimeError(get_capa_import_error_message(error)) from error

    _raise_if_cancelled(should_cancel)
    rules, rules_root, rules_count, rules_cache_id = _load_rules(rules_path, progress_callback, should_cancel)

    extractor = _create_cancellable_binja_extractor(bextractor, bv, should_cancel, progress_callback)

    _raise_if_cancelled(should_cancel)
    _report_progress(progress_callback, "calculating analysis")
    total_functions = len(tuple(extractor.get_functions()))
    extractor.set_function_progress_total(total_functions)

    _raise_if_cancelled(should_cancel)
    _report_progress(progress_callback, "extracting features", 0, total_functions)
    capabilities = ccommon.find_capabilities(rules, extractor, disable_progress=True)

    input_path = Path(sample_path or "binaryninja-database")
    _raise_if_cancelled(should_cancel)
    _report_progress(progress_callback, "collecting metadata")
    meta = capa.loader.collect_metadata(
        [],
        input_path,
        capa.features.common.FORMAT_AUTO,
        capa.features.common.OS_AUTO,
        [rules_root],
        extractor,
        capabilities,
    )

    _raise_if_cancelled(should_cancel)
    _report_progress(progress_callback, "computing layout")
    meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)

    _raise_if_cancelled(should_cancel)
    _report_progress(progress_callback, "checking file limitations")
    limitation_found = ccommon.has_static_limitation(rules, capabilities, is_standalone=False)

    _raise_if_cancelled(should_cancel)
    _report_progress(progress_callback, "collecting results")
    doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)

    return {
        "doc": doc,
        "rules_path": rules_path,
        "rules_count": rules_count,
        "limitation_found": limitation_found,
        "rules_cache_id": rules_cache_id,
    }
