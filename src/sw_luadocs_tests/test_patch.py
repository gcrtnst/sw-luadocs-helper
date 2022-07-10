import re
import sw_luadocs.flatdoc
import sw_luadocs.patch
import unittest


class TestAsPattern(unittest.TestCase):
    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.patch.as_pattern(None)

    def test_main(self):
        for (
            input_v,
            input_flags,
            expected_pattern_pattern,
            expected_pattern_flags,
        ) in [
            (re.compile("test", flags=re.ASCII), 0, "test", re.ASCII),
            ("test", re.ASCII, "test", re.ASCII),
        ]:
            with self.subTest(v=input_v):
                actual_pattern = sw_luadocs.patch.as_pattern(input_v, flags=input_flags)
                self.assertIs(type(actual_pattern), re.Pattern)
                self.assertEqual(actual_pattern.pattern, expected_pattern_pattern)
                self.assertEqual(actual_pattern.flags, expected_pattern_flags)


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
                actual_selector = sw_luadocs.patch.Selector(
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
        selector = sw_luadocs.patch.Selector()
        with self.assertRaises(TypeError):
            selector.select([None])

    def test_main(self):
        for input_selector, input_flatdoc, expected_sl_list in [
            (sw_luadocs.patch.Selector(), [], []),
            (
                sw_luadocs.patch.Selector(),
                [sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head")],
                [slice(0, 1)],
            ),
            (
                sw_luadocs.patch.Selector(section=0),
                [sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head")],
                [],
            ),
            (
                sw_luadocs.patch.Selector(section=1),
                [sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head")],
                [slice(0, 1)],
            ),
            (
                sw_luadocs.patch.Selector(kind="head"),
                [sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head")],
                [slice(0, 1)],
            ),
            (
                sw_luadocs.patch.Selector(kind="body"),
                [sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body")],
                [slice(0, 1)],
            ),
            (
                sw_luadocs.patch.Selector(kind="code"),
                [sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code")],
                [slice(0, 1)],
            ),
            (
                sw_luadocs.patch.Selector(kind="head"),
                [sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body")],
                [],
            ),
            (
                sw_luadocs.patch.Selector(kind="body"),
                [sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code")],
                [],
            ),
            (
                sw_luadocs.patch.Selector(kind="code"),
                [sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head")],
                [],
            ),
            (
                sw_luadocs.patch.Selector(),
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
                sw_luadocs.patch.Selector(section=0),
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
                sw_luadocs.patch.Selector(section=1),
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
                sw_luadocs.patch.Selector(section=2),
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
                sw_luadocs.patch.Selector(kind="head"),
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
                sw_luadocs.patch.Selector(kind="body"),
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
                sw_luadocs.patch.Selector(kind="code"),
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
                sw_luadocs.patch.Selector(start=1),
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
                sw_luadocs.patch.Selector(stop=7),
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
                sw_luadocs.patch.Selector(start=-7),
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
                sw_luadocs.patch.Selector(stop=-1),
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
                sw_luadocs.patch.Selector(section=1, kind="code", start=1, stop=-1),
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
                actual_modifier = sw_luadocs.patch.JoinModifier(sep=input_sep)
                self.assertEqual(actual_modifier._sep, expected_sep)


class TestJoinModifierModify(unittest.TestCase):
    def test_invalid_type(self):
        modifier = sw_luadocs.patch.JoinModifier()
        with self.assertRaises(TypeError):
            modifier.modify([None])

    def test_main(self):
        for input_modifier, input_flatdoc, expected_flatdoc in [
            (sw_luadocs.patch.JoinModifier(), [], []),
            (
                sw_luadocs.patch.JoinModifier(),
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
            ),
            (
                sw_luadocs.patch.JoinModifier(),
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
            ),
            (
                sw_luadocs.patch.JoinModifier(),
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
            ),
            (
                sw_luadocs.patch.JoinModifier(),
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
                sw_luadocs.patch.JoinModifier(sep=", "),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="h3", kind="head"),
                ],
                [sw_luadocs.flatdoc.FlatElem(txt="h1, h2, h3", kind="head")],
            ),
            (
                sw_luadocs.patch.JoinModifier(sep=", "),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b3", kind="body"),
                ],
                [sw_luadocs.flatdoc.FlatElem(txt="b1, b2, b3", kind="body")],
            ),
            (
                sw_luadocs.patch.JoinModifier(sep=", "),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c3", kind="code"),
                ],
                [sw_luadocs.flatdoc.FlatElem(txt="c1, c2, c3", kind="code")],
            ),
            (
                sw_luadocs.patch.JoinModifier(sep=", "),
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
                sw_luadocs.patch.JoinModifier(sep="::"),
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


class TestLineSplitModifierInit(unittest.TestCase):
    def test_main(self):
        modifier = sw_luadocs.patch.LineSplitModifier(line_pattern=".")
        self.assertIs(type(modifier._line_pattern), re.Pattern)
        self.assertEqual(modifier._line_pattern.pattern, ".")
        self.assertEqual(modifier._line_pattern.flags, re.ASCII)


class TestLineSplitModifierModify(unittest.TestCase):
    def test_invalid_type(self):
        modifier = sw_luadocs.patch.LineSplitModifier()
        with self.assertRaises(TypeError):
            modifier.modify([None])

    def test_main(self):
        for input_line_pattern, input_flatdoc, expected_flatdoc in [
            ("", [], []),
            (
                "",
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
                "",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h1\nh2\nh3", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1\nb2\nb3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1\nc2\nc3", kind="code"),
                ],
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
            ),
            (
                r"^[hbc]2$",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h1\nh2\nh3", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1\nb2\nb3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1\nc2\nc3", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2\nh3", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2\nb3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2\nc3", kind="code"),
                ],
            ),
            (
                r"^[hbc]3$",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h1\nh2\nh3", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1\nb2\nb3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1\nc2\nc3", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h1\nh2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="h3", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1\nb2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1\nc2", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c3", kind="code"),
                ],
            ),
        ]:
            with self.subTest(line_pattern=input_line_pattern, flatdoc=input_flatdoc):
                input_modifier = sw_luadocs.patch.LineSplitModifier(
                    line_pattern=input_line_pattern
                )
                input_flatdoc_copy = input_flatdoc[:]
                actual_flatdoc = input_modifier.modify(input_flatdoc_copy)
                self.assertEqual(actual_flatdoc, expected_flatdoc)
                self.assertIsNot(actual_flatdoc, input_flatdoc_copy)
                self.assertEqual(input_flatdoc_copy, input_flatdoc)


class TestPatchInit(unittest.TestCase):
    def test_invalid_type(self):
        for selector, modifier in [
            (None, sw_luadocs.patch.JoinModifier()),
            (sw_luadocs.patch.Selector(), None),
        ]:
            with self.subTest(selector=selector, modifier=modifier):
                with self.assertRaises(TypeError):
                    sw_luadocs.patch.Patch(selector=selector, modifier=modifier)


class TestPatchApply(unittest.TestCase):
    def test_invalid_type(self):
        patch = sw_luadocs.patch.Patch(
            selector=sw_luadocs.patch.Selector(), modifier=MockModifier([])
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
            (sw_luadocs.patch.Selector(), [], [], [], []),
            (
                sw_luadocs.patch.Selector(start=1),
                [],
                [sw_luadocs.flatdoc.FlatElem(txt="1", kind="head")],
                [sw_luadocs.flatdoc.FlatElem(txt="1", kind="head")],
                [],
            ),
            (
                sw_luadocs.patch.Selector(),
                [[]],
                [sw_luadocs.flatdoc.FlatElem(txt="1", kind="head")],
                [],
                [[sw_luadocs.flatdoc.FlatElem(txt="1", kind="head")]],
            ),
            (
                sw_luadocs.patch.Selector(),
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
                sw_luadocs.patch.Selector(start=9),
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
                sw_luadocs.patch.Selector(kind="body"),
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
                sw_luadocs.patch.Selector(kind="body"),
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
                patch = sw_luadocs.patch.Patch(
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
            {"op": "split_line", "extra": None},
        ]:
            with self.subTest(d=d):
                with self.assertRaises(ValueError):
                    sw_luadocs.patch.patch_from_dict(d)

    def test_main(self):
        for (
            input_d,
            expected_selector_section,
            expected_selector_kind,
            expected_selector_start,
            expected_selector_stop,
            expected_modifier_cls,
            expected_modifier_sep,
            expected_modifier_line_pattern,
        ) in [
            (
                {"op": "join"},
                None,
                None,
                None,
                None,
                sw_luadocs.patch.JoinModifier,
                "\n\n",
                "",
            ),
            (
                {"op": "split_line"},
                None,
                None,
                None,
                None,
                sw_luadocs.patch.LineSplitModifier,
                "",
                "",
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
                sw_luadocs.patch.JoinModifier,
                "4",
                "",
            ),
            (
                {
                    "op": "split_line",
                    "section": 1,
                    "kind": "body",
                    "start": 2,
                    "stop": 3,
                    "line_pattern": "4",
                },
                1,
                "body",
                2,
                3,
                sw_luadocs.patch.LineSplitModifier,
                "",
                "4",
            ),
        ]:
            with self.subTest(d=input_d):
                actual_patch = sw_luadocs.patch.patch_from_dict(input_d)
                self.assertEqual(
                    actual_patch._selector._section, expected_selector_section
                )
                self.assertEqual(actual_patch._selector._kind, expected_selector_kind)
                self.assertEqual(actual_patch._selector._start, expected_selector_start)
                self.assertEqual(actual_patch._selector._stop, expected_selector_stop)
                self.assertIs(type(actual_patch._modifier), expected_modifier_cls)
                if expected_modifier_cls is sw_luadocs.patch.JoinModifier:
                    self.assertEqual(actual_patch._modifier._sep, expected_modifier_sep)
                if expected_modifier_cls is sw_luadocs.patch.LineSplitModifier:
                    self.assertEqual(
                        actual_patch._modifier._line_pattern.pattern,
                        expected_modifier_line_pattern,
                    )


class TestAsPatch(unittest.TestCase):
    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.patch.as_patch(None)

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
                sw_luadocs.patch.Patch(
                    selector=sw_luadocs.patch.Selector(
                        section=1, kind="body", start=2, stop=3
                    ),
                    modifier=sw_luadocs.patch.JoinModifier(sep="4"),
                ),
                1,
                "body",
                2,
                3,
                sw_luadocs.patch.JoinModifier,
                "4",
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
                sw_luadocs.patch.JoinModifier,
                "4",
            ),
        ]:
            with self.subTest(v=input_v):
                actual_patch = sw_luadocs.patch.as_patch(input_v)
                self.assertIs(type(actual_patch), sw_luadocs.patch.Patch)
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
                    sw_luadocs.patch.apply_patch_list(flatdoc, patch_list)

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
                    sw_luadocs.patch.Patch(
                        selector=sw_luadocs.patch.Selector(kind="body"),
                        modifier=sw_luadocs.patch.JoinModifier(sep=", "),
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
                    sw_luadocs.flatdoc.FlatElem(txt="body#1\nbody#2", kind="body"),
                ],
                [
                    sw_luadocs.patch.Patch(
                        selector=sw_luadocs.patch.Selector(kind="body"),
                        modifier=sw_luadocs.patch.LineSplitModifier(
                            line_pattern="body"
                        ),
                    ),
                    sw_luadocs.patch.Patch(
                        selector=sw_luadocs.patch.Selector(kind="body"),
                        modifier=sw_luadocs.patch.JoinModifier(sep=", "),
                    ),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="head", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="body#1, body#2", kind="body"),
                ],
            ),
        ]:
            with self.subTest(flatdoc=input_flatdoc, patch_list=input_patch_list):
                actual_flatdoc = sw_luadocs.patch.apply_patch_list(
                    input_flatdoc, input_patch_list
                )
                self.assertEqual(actual_flatdoc, expected_flatdoc)


class MockModifier(sw_luadocs.patch.Modifier):
    def __init__(self, ret_list):
        self.arg_list = []
        self.ret_list = ret_list[:]
        self.idx = 0

    def modify(self, flatdoc):
        self.arg_list.append(flatdoc[:])
        ret = self.ret_list[self.idx]
        self.idx += 1
        return ret
