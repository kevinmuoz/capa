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

class CapaExplorerProgramAnalysisModel:
    def iter_capability_rules(self, doc):
        import capa.render.utils as rutils

        yield from rutils.capability_rules(doc)

    def collect_rules_by_function(self, doc, include_location, get_function_start):
        grouped = {}

        from capa.features.address import AbsoluteVirtualAddress

        for rule in self.iter_capability_rules(doc):
            counts = {}
            for location_frozen, _ in rule.matches:
                location = location_frozen.to_capa()
                if not isinstance(location, AbsoluteVirtualAddress):
                    continue
                if not include_location(location):
                    continue

                function_start = get_function_start(int(location))
                if function_start is None:
                    continue

                counts[function_start] = counts.get(function_start, 0) + 1

            for function_start, count in counts.items():
                grouped.setdefault(function_start, []).append((rule, count))

        return grouped

    def collect_rules_by_program(self, doc, include_location):
        rows = []

        for rule in self.iter_capability_rules(doc):
            matches = []
            for location_frozen, match in rule.matches:
                location = location_frozen.to_capa()
                if not include_location(location):
                    continue
                matches.append((location, match))

            if matches:
                rows.append((rule, matches))

        return rows

    def capture_details_for_location(self, match, location) -> str:
        import capa.features.common

        for capture, addrs in sorted(match.captures.items()):
            for frozen_addr in addrs:
                if location == frozen_addr.to_capa():
                    return f"\"{capa.features.common.escape_string(capture)}\""
        return ""

    def feature_kind(self, feature) -> str:
        import capa.features.freeze.features as frzf

        if isinstance(feature, frzf.CharacteristicFeature):
            if feature.characteristic in ("embedded pe",):
                return "bytes"
            if feature.characteristic in ("loop", "recursive call", "tight loop"):
                return "plain"
            return "instruction"

        if isinstance(feature, frzf.MatchFeature):
            return "match"

        if isinstance(feature, (frzf.RegexFeature, frzf.SubstringFeature, frzf.StringFeature)):
            return "string"

        if isinstance(feature, frzf.BasicBlockFeature):
            return "block"

        if isinstance(
            feature,
            (
                frzf.BytesFeature,
                frzf.APIFeature,
                frzf.MnemonicFeature,
                frzf.NumberFeature,
                frzf.OffsetFeature,
                frzf.OperandNumberFeature,
                frzf.OperandOffsetFeature,
            ),
        ):
            return "instruction"

        if isinstance(feature, frzf.SectionFeature):
            return "bytes"

        if isinstance(
            feature,
            (
                frzf.ImportFeature,
                frzf.ExportFeature,
                frzf.FunctionNameFeature,
                frzf.ArchFeature,
                frzf.OSFeature,
                frzf.FormatFeature,
            ),
        ):
            return "plain"

        return "plain"

    def feature_to_display(self, feature) -> str:
        import capa.features.common
        import capa.features.freeze.features as frzf

        key = str(feature.type)
        value = feature.model_dump(by_alias=True).get(feature.type)

        if value:
            if isinstance(feature, frzf.StringFeature):
                value = f"\"{capa.features.common.escape_string(value)}\""

            if isinstance(feature, frzf.PropertyFeature) and feature.access is not None:
                key = f"property/{feature.access}"
            elif isinstance(feature, frzf.OperandNumberFeature):
                key = f"operand[{feature.index}].number"
            elif isinstance(feature, frzf.OperandOffsetFeature):
                key = f"operand[{feature.index}].offset"

            if feature.description:
                return f"{key}({value} = {feature.description})"
            return f"{key}({value})"

        return f"{key}"
