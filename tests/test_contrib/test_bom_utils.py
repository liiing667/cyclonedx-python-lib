# This file is part of CycloneDX Python Library
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
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.


from unittest import TestCase

from cyclonedx.contrib.bom.utils import BomDependencyGraphFlatMerger, BomRefDiscriminator
from cyclonedx.exception.model import AmbiguousBomRefException
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.service import Service
from cyclonedx.model.vulnerability import BomTarget, Vulnerability


class TestBomRefDiscriminator(TestCase):

    def test_discriminate_and_reset_manually(self) -> None:
        bomref1 = BomRef('djdlkfjdslkf')
        bomref2 = BomRef('djdlkfjdslkf')
        self.assertEqual(bomref1.value, bomref2.value, 'blank')
        discr = BomRefDiscriminator([bomref1, bomref2])
        self.assertEqual(bomref1.value, bomref2.value, 'init')
        discr.discriminate()
        self.assertNotEqual(bomref1.value, bomref2.value, 'should be discriminated')
        discr.reset()
        self.assertEqual('djdlkfjdslkf', bomref1.value)
        self.assertEqual('djdlkfjdslkf', bomref2.value)

    def test_discriminate_and_reset_with(self) -> None:
        bomref1 = BomRef('djdlkfjdslkf')
        bomref2 = BomRef('djdlkfjdslkf')
        self.assertEqual(bomref1.value, bomref2.value, 'blank')
        discr = BomRefDiscriminator([bomref1, bomref2])
        self.assertEqual(bomref1.value, bomref2.value, 'init')
        with discr:
            self.assertNotEqual(bomref1.value, bomref2.value, 'should be discriminated')
        self.assertEqual('djdlkfjdslkf', bomref1.value)
        self.assertEqual('djdlkfjdslkf', bomref2.value)

    def test_from_bom_leaves_unique_referenced_refs_untouched(self) -> None:
        component = Component(name='foo', bom_ref='foo-ref')
        target = BomTarget(ref='foo-ref')
        bom = Bom(components=[component])
        bom.vulnerabilities.add(Vulnerability(bom_ref='vuln-ref', id='CVE-1', affects=[target]))
        with BomRefDiscriminator.from_bom(bom):
            self.assertEqual('foo-ref', component.bom_ref.value)
            self.assertEqual('foo-ref', target.ref)
        self.assertEqual('foo-ref', component.bom_ref.value)
        self.assertEqual('foo-ref', target.ref)

    def test_from_bom_discriminates_unreferenced_duplicates(self) -> None:
        component1 = Component(name='foo', bom_ref='dup-ref')
        component2 = Component(name='bar', bom_ref='dup-ref')
        bom = Bom(components=[component1, component2])
        bom.vulnerabilities.add(Vulnerability(
            bom_ref='vuln-ref', id='CVE-1', affects=[BomTarget(ref='other-ref')]))
        with BomRefDiscriminator.from_bom(bom):
            self.assertNotEqual(component1.bom_ref.value, component2.bom_ref.value)
            self.assertIn('dup-ref', (component1.bom_ref.value, component2.bom_ref.value))
        self.assertEqual('dup-ref', component1.bom_ref.value)
        self.assertEqual('dup-ref', component2.bom_ref.value)

    def test_from_bom_raises_on_ambiguous_reference(self) -> None:
        component1 = Component(name='foo', bom_ref='dup-ref')
        component2 = Component(name='bar', bom_ref='dup-ref')
        target = BomTarget(ref='dup-ref')
        bom = Bom(components=[component1, component2])
        bom.vulnerabilities.add(Vulnerability(bom_ref='vuln-ref', id='CVE-1', affects=[target]))
        discr = BomRefDiscriminator.from_bom(bom)
        with self.assertRaises(AmbiguousBomRefException):
            discr.discriminate()
        # bom-refs must be unmodified, as discrimination was refused
        self.assertEqual('dup-ref', component1.bom_ref.value)
        self.assertEqual('dup-ref', component2.bom_ref.value)
        self.assertEqual('dup-ref', target.ref)

    def test_from_bom_raises_on_ambiguous_reference_with(self) -> None:
        component1 = Component(name='foo', bom_ref='dup-ref')
        component2 = Component(name='bar', bom_ref='dup-ref')
        bom = Bom(components=[component1, component2])
        bom.vulnerabilities.add(Vulnerability(
            bom_ref='vuln-ref', id='CVE-1', affects=[BomTarget(ref='dup-ref')]))
        with self.assertRaises(AmbiguousBomRefException):
            with BomRefDiscriminator.from_bom(bom):
                pass  # pragma: no cover
        self.assertEqual('dup-ref', component1.bom_ref.value)
        self.assertEqual('dup-ref', component2.bom_ref.value)

    def test_from_bom_raises_on_ambiguous_service_reference(self) -> None:
        component = Component(name='foo', bom_ref='dup-ref')
        service = Service(name='bar', bom_ref='dup-ref')
        bom = Bom(components=[component], services=[service])
        bom.vulnerabilities.add(Vulnerability(
            bom_ref='vuln-ref', id='CVE-1', affects=[BomTarget(ref='dup-ref')]))
        with self.assertRaises(AmbiguousBomRefException):
            BomRefDiscriminator.from_bom(bom).discriminate()


class TestBomDependencyGraphFlatMerger(TestCase):

    def test_flatten_merge_and_reset_manually(self) -> None:
        root_bom_ref = BomRef('root_bom_ref')
        component1_bom_ref = BomRef('component1_bom_ref')
        component2_bom_ref = BomRef('component2_bom_ref')
        component3_bom_ref = BomRef('component3_bom_ref')
        component4_bom_ref = BomRef('component4_bom_ref')
        component5_bom_ref = BomRef('component5_bom_ref')
        bom = Bom(dependencies=[
            Dependency(
                root_bom_ref,
                dependencies=[
                    component1_bom_dep := Dependency(
                        component1_bom_ref,
                        dependencies=[
                            component2_bom_dep := Dependency(
                                component2_bom_ref,
                                dependencies=[
                                    component3_bom_dep := Dependency(component3_bom_ref),
                                ]
                            ),
                        ]
                    ),
                    component2_bom_dep2 := Dependency(
                        component2_bom_ref,
                        dependencies=[
                            component4_bom_dep := Dependency(component4_bom_ref),
                        ]
                    ),
                ]
            ),
            component3_bom_dep2 := Dependency(
                component3_bom_ref,
                dependencies=[
                    component4_bom_dep2 := Dependency(component4_bom_ref),
                ]
            ),
            Dependency(component5_bom_ref, (
                component1_bom_dep,
                component2_bom_dep,
                component2_bom_dep2,
                component3_bom_dep,
                component3_bom_dep2,
                component4_bom_dep,
                component4_bom_dep2,
                Dependency(root_bom_ref)
            ))
        ])
        bom_dependencies = bom.dependencies
        merger = BomDependencyGraphFlatMerger(bom)
        merger.flatten_merge()
        self.assertEqual(6, len(bom.dependencies), 'not expected len()')
        self.assertSetEqual({
            Dependency(root_bom_ref, (Dependency(component1_bom_ref), Dependency(component2_bom_ref))),
            Dependency(component1_bom_ref, (Dependency(component2_bom_ref), )),
            Dependency(component2_bom_ref, (Dependency(component3_bom_ref), Dependency(component4_bom_ref), )),
            Dependency(component3_bom_ref, (Dependency(component4_bom_ref), )),
            Dependency(component4_bom_ref),
            Dependency(component5_bom_ref, (
                Dependency(root_bom_ref),
                Dependency(component1_bom_ref),
                Dependency(component2_bom_ref),
                Dependency(component3_bom_ref),
                Dependency(component4_bom_ref),
            )),
        }, bom.dependencies)
        merger.reset()
        self.assertIs(bom_dependencies, bom.dependencies)
        self.assertSetEqual(bom_dependencies, bom.dependencies)

    def test_flatten_merge_and_reset_with(self) -> None:
        root_bom_ref = BomRef('root_bom_ref')
        component1_bom_ref = BomRef('component1_bom_ref')
        component2_bom_ref = BomRef('component2_bom_ref')
        component3_bom_ref = BomRef('component3_bom_ref')
        component4_bom_ref = BomRef('component4_bom_ref')
        component5_bom_ref = BomRef('component5_bom_ref')
        bom = Bom(dependencies=[
            Dependency(
                root_bom_ref,
                dependencies=[
                    component1_bom_dep := Dependency(
                        component1_bom_ref,
                        dependencies=[
                            component2_bom_dep := Dependency(
                                component2_bom_ref,
                                dependencies=[
                                    component3_bom_dep := Dependency(component3_bom_ref),
                                ]
                            ),
                        ]
                    ),
                    component2_bom_dep2 := Dependency(
                        component2_bom_ref,
                        dependencies=[
                            component4_bom_dep := Dependency(component4_bom_ref),
                        ]
                    ),
                ]
            ),
            component3_bom_dep2 := Dependency(
                component3_bom_ref,
                dependencies=[
                    component4_bom_dep2 := Dependency(component4_bom_ref),
                ]
            ),
            Dependency(component5_bom_ref, (
                Dependency(root_bom_ref),
                component1_bom_dep,
                component2_bom_dep,
                component2_bom_dep2,
                component3_bom_dep,
                component3_bom_dep2,
                component4_bom_dep,
                component4_bom_dep2,
            ))
        ])
        bom_dependencies = bom.dependencies
        merger = BomDependencyGraphFlatMerger(bom)
        with merger:
            self.assertEqual(6, len(bom.dependencies), 'not expected len()')
            self.assertSetEqual({
                Dependency(root_bom_ref, (Dependency(component1_bom_ref), Dependency(component2_bom_ref))),
                Dependency(component1_bom_ref, (Dependency(component2_bom_ref), )),
                Dependency(component2_bom_ref, (Dependency(component3_bom_ref), Dependency(component4_bom_ref), )),
                Dependency(component3_bom_ref, (Dependency(component4_bom_ref), )),
                Dependency(component4_bom_ref),
                Dependency(component5_bom_ref, (
                    Dependency(root_bom_ref),
                    Dependency(component1_bom_ref),
                    Dependency(component2_bom_ref),
                    Dependency(component3_bom_ref),
                    Dependency(component4_bom_ref),
                )),
            }, bom.dependencies)
        self.assertIs(bom_dependencies, bom.dependencies)
        self.assertSetEqual(bom_dependencies, bom.dependencies)
