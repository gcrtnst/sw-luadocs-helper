import sw_luadocs.flatdoc
import sw_luadocs.hint
import unittest


class TestSelectorInit(unittest.TestCase):
    def test_main(self):
        for (
            input_section,
            input_kind,
            input_start,
            input_stop,
            expected_section,
            expected_kind,
            expected_start,
            expected_stop,
        ) in [
            (1, "body", 2, 3, 1, "body", 2, 3),
            ("1", "body", "2", "3", 1, "body", 2, 3),
            (None, None, None, None, None, None, None, None),
        ]:
            with self.subTest(
                section=input_section,
                kind=input_kind,
                start=input_start,
                stop=input_stop,
            ):
                actual_selector = sw_luadocs.hint.Selector(
                    section=input_section,
                    kind=input_kind,
                    start=input_start,
                    stop=input_stop,
                )
                self.assertEqual(actual_selector._section, expected_section)
                self.assertEqual(actual_selector._kind, expected_kind)
                self.assertEqual(actual_selector._start, expected_start)
                self.assertEqual(actual_selector._stop, expected_stop)


class TestSelectorSelect(unittest.TestCase):
    def test_invalid_type(self):
        selector = sw_luadocs.hint.Selector()
        with self.assertRaises(TypeError):
            selector.select([None])

    def test_main(self):
        for input_selector, input_flatdoc, expected_sl_list in [
            (sw_luadocs.hint.Selector(), [], []),
            (
                sw_luadocs.hint.Selector(),
                [sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head")],
                [slice(0, 1)],
            ),
            (
                sw_luadocs.hint.Selector(section=0),
                [sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head")],
                [],
            ),
            (
                sw_luadocs.hint.Selector(section=1),
                [sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head")],
                [slice(0, 1)],
            ),
            (
                sw_luadocs.hint.Selector(kind="head"),
                [sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head")],
                [slice(0, 1)],
            ),
            (
                sw_luadocs.hint.Selector(kind="body"),
                [sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body")],
                [slice(0, 1)],
            ),
            (
                sw_luadocs.hint.Selector(kind="code"),
                [sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code")],
                [slice(0, 1)],
            ),
            (
                sw_luadocs.hint.Selector(kind="head"),
                [sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body")],
                [],
            ),
            (
                sw_luadocs.hint.Selector(kind="body"),
                [sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code")],
                [],
            ),
            (
                sw_luadocs.hint.Selector(kind="code"),
                [sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head")],
                [],
            ),
            (
                sw_luadocs.hint.Selector(),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                [slice(0, 8)],
            ),
            (
                sw_luadocs.hint.Selector(section=0),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                [slice(0, 2)],
            ),
            (
                sw_luadocs.hint.Selector(section=1),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                [slice(2, 5)],
            ),
            (
                sw_luadocs.hint.Selector(section=2),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                [slice(5, 8)],
            ),
            (
                sw_luadocs.hint.Selector(kind="head"),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                [slice(2, 3), slice(5, 6)],
            ),
            (
                sw_luadocs.hint.Selector(kind="body"),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                [slice(0, 1), slice(3, 4), slice(6, 7)],
            ),
            (
                sw_luadocs.hint.Selector(kind="code"),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                [slice(1, 2), slice(4, 5), slice(7, 8)],
            ),
            (
                sw_luadocs.hint.Selector(start=1),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                [slice(1, 8)],
            ),
            (
                sw_luadocs.hint.Selector(stop=7),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                [slice(0, 7)],
            ),
            (
                sw_luadocs.hint.Selector(start=-7),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                [slice(1, 8)],
            ),
            (
                sw_luadocs.hint.Selector(stop=-1),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                [slice(0, 7)],
            ),
            (
                sw_luadocs.hint.Selector(section=1, kind="code", start=1, stop=-1),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="c0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                ],
                [slice(3, 4)],
            ),
        ]:
            with self.subTest(selector=input_selector, flatdoc=input_flatdoc):
                actual_sl_list = input_selector.select(input_flatdoc)
                self.assertEqual(actual_sl_list, expected_sl_list)


class TestJoinModifierInit(unittest.TestCase):
    def test_main(self):
        for input_sep, expected_sep in [("abc", "abc"), (123, "123")]:
            with self.subTest(sep=input_sep):
                actual_modifier = sw_luadocs.hint.JoinModifier(sep=input_sep)
                self.assertEqual(actual_modifier._sep, expected_sep)


class TestJoinModifierModify(unittest.TestCase):
    def test_invalid_type(self):
        modifier = sw_luadocs.hint.JoinModifier()
        with self.assertRaises(TypeError):
            modifier.modify([None])

    def test_main(self):
        for input_modifier, input_flatdoc, expected_flatdoc in [
            (sw_luadocs.hint.JoinModifier(), [], []),
            (
                sw_luadocs.hint.JoinModifier(),
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
            ),
            (
                sw_luadocs.hint.JoinModifier(),
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
            ),
            (
                sw_luadocs.hint.JoinModifier(),
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
            ),
            (
                sw_luadocs.hint.JoinModifier(),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
            ),
            (
                sw_luadocs.hint.JoinModifier(sep=", "),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="h3", kind="head"),
                ],
                [sw_luadocs.flatdoc.FlatElem(txt="h1, h2, h3", kind="head")],
            ),
            (
                sw_luadocs.hint.JoinModifier(sep=", "),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b3", kind="body"),
                ],
                [sw_luadocs.flatdoc.FlatElem(txt="b1, b2, b3", kind="body")],
            ),
            (
                sw_luadocs.hint.JoinModifier(sep=", "),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c3", kind="code"),
                ],
                [sw_luadocs.flatdoc.FlatElem(txt="c1, c2, c3", kind="code")],
            ),
            (
                sw_luadocs.hint.JoinModifier(sep=", "),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="h3", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c3", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h1, h2, h3", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1, b2, b3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1, c2, c3", kind="code"),
                ],
            ),
            (
                sw_luadocs.hint.JoinModifier(sep="::"),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="h3", kind="head"),
                ],
                [sw_luadocs.flatdoc.FlatElem(txt="h1::h2::h3", kind="head")],
            ),
        ]:
            input_flatdoc_copy = input_flatdoc[:]
            actual_flatdoc = input_modifier.modify(input_flatdoc_copy)
            self.assertEqual(actual_flatdoc, expected_flatdoc)
            self.assertIsNot(actual_flatdoc, input_flatdoc_copy)
            self.assertEqual(input_flatdoc_copy, input_flatdoc)


class TestSplitModifierInit(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.hint.SplitModifier(sep="")

    def test_main(self):
        for input_sep, expected_sep in [("abc", "abc"), (123, "123")]:
            with self.subTest(sep=input_sep):
                actual_modifier = sw_luadocs.hint.SplitModifier(sep=input_sep)
                self.assertEqual(actual_modifier._sep, expected_sep)


class TestSplitModifierModify(unittest.TestCase):
    def test_invalid_type(self):
        modifier = sw_luadocs.hint.SplitModifier()
        with self.assertRaises(TypeError):
            modifier.modify([None])

    def test_main(self):
        for input_modifier, input_flatdoc, expected_flatdoc in [
            (sw_luadocs.hint.SplitModifier(), [], []),
            (
                sw_luadocs.hint.SplitModifier(sep=","),
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
            ),
            (
                sw_luadocs.hint.SplitModifier(sep=","),
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
            ),
            (
                sw_luadocs.hint.SplitModifier(sep=","),
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
            ),
            (
                sw_luadocs.hint.SplitModifier(sep=","),
                [sw_luadocs.flatdoc.FlatElem(txt="abc,def,ghi", kind="head")],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="abc", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="def", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ghi", kind="head"),
                ],
            ),
            (
                sw_luadocs.hint.SplitModifier(sep=","),
                [sw_luadocs.flatdoc.FlatElem(txt="abc,def,ghi", kind="body")],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="abc", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="def", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="ghi", kind="body"),
                ],
            ),
            (
                sw_luadocs.hint.SplitModifier(sep=","),
                [sw_luadocs.flatdoc.FlatElem(txt="abc,def,ghi", kind="code")],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="abc", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="def", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="ghi", kind="code"),
                ],
            ),
            (
                sw_luadocs.hint.SplitModifier(sep=","),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="2,3,4", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="5", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="6,7,8", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="9", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="10,11,12", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="3", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="4", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="5", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="6", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="7", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="8", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="9", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="10", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="11", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="12", kind="code"),
                ],
            ),
        ]:
            with self.subTest(modifier=input_modifier, flatdoc=input_flatdoc):
                input_flatdoc_copy = input_flatdoc[:]
                actual_flatdoc = input_modifier.modify(input_flatdoc_copy)
                self.assertEqual(actual_flatdoc, expected_flatdoc)
                self.assertIsNot(actual_flatdoc, input_flatdoc_copy)
                self.assertIsNot(input_flatdoc_copy, input_flatdoc)


class TestPatchInit(unittest.TestCase):
    def test_invalid_type(self):
        for selector, modifier in [
            (None, sw_luadocs.hint.JoinModifier()),
            (sw_luadocs.hint.Selector(), None),
        ]:
            with self.subTest(selector=selector, modifier=modifier):
                with self.assertRaises(TypeError):
                    sw_luadocs.hint.Patch(selector=selector, modifier=modifier)


class TestPatchApply(unittest.TestCase):
    def test_invalid_type(self):
        patch = sw_luadocs.hint.Patch(
            selector=sw_luadocs.hint.Selector(), modifier=MockModifier([])
        )
        with self.assertRaises(TypeError):
            patch.apply([None])

    def test_main(self):
        for (
            input_selector,
            input_modifier_ret_list,
            input_flatdoc,
            expected_flatdoc,
            expected_modifier_arg_list,
        ) in [
            (sw_luadocs.hint.Selector(), [], [], [], []),
            (
                sw_luadocs.hint.Selector(start=1),
                [],
                [sw_luadocs.flatdoc.FlatElem(txt="1", kind="head")],
                [sw_luadocs.flatdoc.FlatElem(txt="1", kind="head")],
                [],
            ),
            (
                sw_luadocs.hint.Selector(),
                [[]],
                [sw_luadocs.flatdoc.FlatElem(txt="1", kind="head")],
                [],
                [[sw_luadocs.flatdoc.FlatElem(txt="1", kind="head")]],
            ),
            (
                sw_luadocs.hint.Selector(),
                [
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="2", kind="head"),
                        sw_luadocs.flatdoc.FlatElem(txt="3", kind="head"),
                    ]
                ],
                [sw_luadocs.flatdoc.FlatElem(txt="1", kind="head")],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="3", kind="head"),
                ],
                [[sw_luadocs.flatdoc.FlatElem(txt="1", kind="head")]],
            ),
            (
                sw_luadocs.hint.Selector(start=9),
                [],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="4", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="5", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="6", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="7", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="8", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="9", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="4", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="5", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="6", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="7", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="8", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="9", kind="code"),
                ],
                [],
            ),
            (
                sw_luadocs.hint.Selector(kind="body"),
                [[], []],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="4", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="5", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="6", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="7", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="8", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="9", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="4", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="5", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="8", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="9", kind="code"),
                ],
                [
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="2", kind="body"),
                    ],
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="6", kind="body"),
                        sw_luadocs.flatdoc.FlatElem(txt="7", kind="body"),
                    ],
                ],
            ),
            (
                sw_luadocs.hint.Selector(kind="body"),
                [
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="10", kind="body"),
                        sw_luadocs.flatdoc.FlatElem(txt="11", kind="body"),
                    ],
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="12", kind="body"),
                        sw_luadocs.flatdoc.FlatElem(txt="13", kind="body"),
                    ],
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="4", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="5", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="6", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="7", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="8", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="9", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="10", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="11", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="4", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="5", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="12", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="13", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="8", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="9", kind="code"),
                ],
                [
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="2", kind="body"),
                    ],
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="6", kind="body"),
                        sw_luadocs.flatdoc.FlatElem(txt="7", kind="body"),
                    ],
                ],
            ),
        ]:
            with self.subTest(
                selector=input_selector,
                modifier_ret_list=input_modifier_ret_list,
                flatdoc=input_flatdoc,
            ):
                modifier = MockModifier(input_modifier_ret_list)
                patch = sw_luadocs.hint.Patch(
                    selector=input_selector, modifier=modifier
                )
                input_flatdoc_copy = input_flatdoc[:]
                actual_flatdoc = patch.apply(input_flatdoc_copy)
                self.assertEqual(actual_flatdoc, expected_flatdoc)
                self.assertIsNot(actual_flatdoc, input_flatdoc_copy)
                self.assertEqual(input_flatdoc_copy, input_flatdoc)
                self.assertEqual(modifier.arg_list, expected_modifier_arg_list)


class TestPatchFromDict(unittest.TestCase):
    def test_invalid_value(self):
        for d in [
            {},
            {"op": "invalid"},
            {"op": "join", "extra": None},
            {"op": "split", "extra": None},
        ]:
            with self.subTest(d=d):
                with self.assertRaises(ValueError):
                    sw_luadocs.hint.patch_from_dict(d)

    def test_main(self):
        for (
            input_d,
            expected_selector_section,
            expected_selector_kind,
            expected_selector_start,
            expected_selector_stop,
            expected_modifier_cls,
            expected_modifier_sep,
        ) in [
            (
                {"op": "join"},
                None,
                None,
                None,
                None,
                sw_luadocs.hint.JoinModifier,
                "\n\n",
            ),
            (
                {"op": "split"},
                None,
                None,
                None,
                None,
                sw_luadocs.hint.SplitModifier,
                "\n\n",
            ),
            (
                {
                    "op": "join",
                    "section": 1,
                    "kind": "body",
                    "start": 2,
                    "stop": 3,
                    "sep": "4",
                },
                1,
                "body",
                2,
                3,
                sw_luadocs.hint.JoinModifier,
                "4",
            ),
            (
                {
                    "op": "split",
                    "section": 1,
                    "kind": "body",
                    "start": 2,
                    "stop": 3,
                    "sep": "4",
                },
                1,
                "body",
                2,
                3,
                sw_luadocs.hint.SplitModifier,
                "4",
            ),
        ]:
            with self.subTest(d=input_d):
                actual_patch = sw_luadocs.hint.patch_from_dict(input_d)
                self.assertEqual(
                    actual_patch._selector._section, expected_selector_section
                )
                self.assertEqual(actual_patch._selector._kind, expected_selector_kind)
                self.assertEqual(actual_patch._selector._start, expected_selector_start)
                self.assertEqual(actual_patch._selector._stop, expected_selector_stop)
                self.assertIs(type(actual_patch._modifier), expected_modifier_cls)
                self.assertEqual(actual_patch._modifier._sep, expected_modifier_sep)


class TestAsPatch(unittest.TestCase):
    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.hint.as_patch(None)

    def test_main(self):
        for (
            input_v,
            expected_selector_section,
            expected_selector_kind,
            expected_selector_start,
            expected_selector_stop,
            expected_modifier_cls,
            expected_modifier_sep,
        ) in [
            (
                sw_luadocs.hint.Patch(
                    selector=sw_luadocs.hint.Selector(
                        section=1, kind="body", start=2, stop=3
                    ),
                    modifier=sw_luadocs.hint.SplitModifier(sep="4"),
                ),
                1,
                "body",
                2,
                3,
                sw_luadocs.hint.SplitModifier,
                "4",
            ),
            (
                {
                    "op": "split",
                    "section": 1,
                    "kind": "body",
                    "start": 2,
                    "stop": 3,
                    "sep": "4",
                },
                1,
                "body",
                2,
                3,
                sw_luadocs.hint.SplitModifier,
                "4",
            ),
        ]:
            with self.subTest(v=input_v):
                actual_patch = sw_luadocs.hint.as_patch(input_v)
                self.assertIs(type(actual_patch), sw_luadocs.hint.Patch)
                self.assertEqual(
                    actual_patch._selector._section, expected_selector_section
                )
                self.assertEqual(actual_patch._selector._kind, expected_selector_kind)
                self.assertEqual(actual_patch._selector._start, expected_selector_start)
                self.assertEqual(actual_patch._selector._stop, expected_selector_stop)
                self.assertIs(type(actual_patch._modifier), expected_modifier_cls)
                self.assertEqual(actual_patch._modifier._sep, expected_modifier_sep)


class TestApplyPatchList(unittest.TestCase):
    def test_invalid_type(self):
        for flatdoc, patch_list in [([None], []), ([], [None])]:
            with self.subTest(flatdoc=flatdoc, patch_list=patch_list):
                with self.assertRaises(TypeError):
                    sw_luadocs.hint.apply_patch_list(flatdoc, patch_list)

    def test_main(self):
        for input_flatdoc, input_patch_list, expected_flatdoc in [
            ([], [], []),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="head", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#2", kind="body"),
                ],
                [],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="head", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#2", kind="body"),
                ],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="head", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#2", kind="body"),
                ],
                [
                    sw_luadocs.hint.Patch(
                        selector=sw_luadocs.hint.Selector(kind="body"),
                        modifier=sw_luadocs.hint.JoinModifier(sep=", "),
                    )
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="head", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#1, body#2", kind="body"),
                ],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="head", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#2", kind="body"),
                ],
                [{"op": "join", "kind": "body", "sep": ", "}],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="head", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#1, body#2", kind="body"),
                ],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="head", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#2", kind="body"),
                ],
                [
                    sw_luadocs.hint.Patch(
                        selector=sw_luadocs.hint.Selector(kind="body"),
                        modifier=sw_luadocs.hint.JoinModifier(sep=", "),
                    ),
                    sw_luadocs.hint.Patch(
                        selector=sw_luadocs.hint.Selector(kind="body"),
                        modifier=sw_luadocs.hint.SplitModifier(sep="#"),
                    ),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="head", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="body", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="1, body", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="2", kind="body"),
                ],
            ),
        ]:
            with self.subTest(flatdoc=input_flatdoc, patch_list=input_patch_list):
                actual_flatdoc = sw_luadocs.hint.apply_patch_list(
                    input_flatdoc, input_patch_list
                )
                self.assertEqual(actual_flatdoc, expected_flatdoc)


class MockModifier(sw_luadocs.hint.Modifier):
    def __init__(self, ret_list):
        self.arg_list = []
        self.ret_list = ret_list[:]
        self.idx = 0

    def modify(self, flatdoc):
        self.arg_list.append(flatdoc[:])
        ret = self.ret_list[self.idx]
        self.idx += 1
        return ret
