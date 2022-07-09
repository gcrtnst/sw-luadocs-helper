import sw_luadocs.flatdoc
import sw_luadocs.hint
import unittest


class TestGetSection(unittest.TestCase):
    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.hint.get_section([None], section_nth=None)

    def test_invalid_index(self):
        for flatdoc, section_nth in [
            ([], 1),
            ([], -2),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                3,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                -4,
            ),
        ]:
            with self.subTest(flatdoc=flatdoc, section_nth=section_nth):
                with self.assertRaises(IndexError):
                    sw_luadocs.hint.get_section(flatdoc, section_nth=section_nth)

    def test_main(self):
        for input_flatdoc, input_section_nth, expected_section in [
            ([], None, slice(None, None)),
            ([], 0, slice(0, 0)),
            ([], -1, slice(0, 0)),
            ([], "0", slice(0, 0)),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                ],
                0,
                slice(0, 2),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                ],
                -1,
                slice(0, 2),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
                0,
                slice(0, 0),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
                -2,
                slice(0, 0),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
                1,
                slice(0, 3),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
                -1,
                slice(0, 3),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
                0,
                slice(0, 2),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
                -2,
                slice(0, 2),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
                1,
                slice(2, 5),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
                -1,
                slice(2, 5),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="code"),
                ],
                0,
                slice(0, 2),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="code"),
                ],
                -3,
                slice(0, 2),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="code"),
                ],
                1,
                slice(2, 3),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="code"),
                ],
                -2,
                slice(2, 3),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="code"),
                ],
                2,
                slice(3, 6),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="code"),
                ],
                -1,
                slice(3, 6),
            ),
        ]:
            with self.subTest(flatdoc=input_flatdoc, section_nth=input_section_nth):
                actual_section = sw_luadocs.hint.get_section(
                    input_flatdoc, input_section_nth
                )
                self.assertEqual(actual_section, expected_section)


class TestJoinFlatElem(unittest.TestCase):
    def test_invalid_value(self):
        for flatdoc, sep in [
            ([], "\n\n"),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="code"),
                ],
                "\n\n",
            ),
        ]:
            with self.subTest(flatdoc=flatdoc, sep=sep):
                with self.assertRaises(ValueError):
                    sw_luadocs.hint.join_flatelem(flatdoc, sep=sep)

    def test_main(self):
        for input_flatdoc, input_sep, expected_flatelem in [
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="body")],
                "\n\n",
                sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="code")],
                "\n\n",
                sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="body"),
                ],
                "\n\n",
                sw_luadocs.flatdoc.FlatElem(txt="a\n\nb\n\nc", kind="body"),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="body"),
                ],
                ", ",
                sw_luadocs.flatdoc.FlatElem(txt="a, b, c", kind="body"),
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="body"),
                ],
                0,
                sw_luadocs.flatdoc.FlatElem(txt="a0b0c", kind="body"),
            ),
        ]:
            with self.subTest(flatdoc=input_flatdoc, sep=input_sep):
                actual_flatelem = sw_luadocs.hint.join_flatelem(
                    input_flatdoc, sep=input_sep
                )
                self.assertEqual(actual_flatelem, expected_flatelem)


class TestSplitFlatElem(unittest.TestCase):
    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.hint.split_flatelem(None, 0)

    def test_invalid_value(self):
        for flatelem, txt_pos in [
            (sw_luadocs.flatdoc.FlatElem(txt="", kind="body"), 1),
            (sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="body"), 0),
            (sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="body"), 9),
            (sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="body"), -9),
        ]:
            with self.subTest(flatelem=flatelem, txt_pos=txt_pos):
                with self.assertRaises(ValueError):
                    sw_luadocs.hint.split_flatelem(flatelem, txt_pos)

    def test_main(self):
        for input_flatelem, input_txt_pos, expected_flatdoc in [
            (
                sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="head"),
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="23456789", kind="head"),
                ],
            ),
            (
                sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="body"),
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="23456789", kind="body"),
                ],
            ),
            (
                sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="code"),
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="23456789", kind="code"),
                ],
            ),
            (
                sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="body"),
                "1",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="23456789", kind="body"),
                ],
            ),
            (
                sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="body"),
                5,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="12345", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="6789", kind="body"),
                ],
            ),
            (
                sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="body"),
                8,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="12345678", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="9", kind="body"),
                ],
            ),
            (
                sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="body"),
                -1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="12345678", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="9", kind="body"),
                ],
            ),
            (
                sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="body"),
                -4,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="12345", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="6789", kind="body"),
                ],
            ),
            (
                sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="body"),
                -8,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="23456789", kind="body"),
                ],
            ),
        ]:
            with self.subTest(flatelem=input_flatelem, txt_pos=input_txt_pos):
                actual_flatdoc = sw_luadocs.hint.split_flatelem(
                    input_flatelem, input_txt_pos
                )
                self.assertEqual(actual_flatdoc, expected_flatdoc)


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


class TestPatcherInit(unittest.TestCase):
    def test_invalid_type(self):
        for selector, modifier in [
            (None, sw_luadocs.hint.JoinModifier()),
            (sw_luadocs.hint.Selector(), None),
        ]:
            with self.subTest(selector=selector, modifier=modifier):
                with self.assertRaises(TypeError):
                    sw_luadocs.hint.Patcher(selector=selector, modifier=modifier)


class TestPatcherPatch(unittest.TestCase):
    def test_invalid_type(self):
        patcher = sw_luadocs.hint.Patcher(
            selector=sw_luadocs.hint.Selector(), modifier=MockModifier([])
        )
        with self.assertRaises(TypeError):
            patcher.patch([None])

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
                patcher = sw_luadocs.hint.Patcher(
                    selector=input_selector, modifier=modifier
                )
                input_flatdoc_copy = input_flatdoc[:]
                actual_flatdoc = patcher.patch(input_flatdoc_copy)
                self.assertEqual(actual_flatdoc, expected_flatdoc)
                self.assertIsNot(actual_flatdoc, input_flatdoc_copy)
                self.assertEqual(input_flatdoc_copy, input_flatdoc)
                self.assertEqual(modifier.arg_list, expected_modifier_arg_list)


class TestPatcherFromDict(unittest.TestCase):
    def test_invalid_value(self):
        for d in [
            {},
            {"op": "invalid"},
            {"op": "join", "extra": None},
            {"op": "split", "extra": None},
        ]:
            with self.subTest(d=d):
                with self.assertRaises(ValueError):
                    sw_luadocs.hint.patcher_from_dict(d)

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
                actual_patcher = sw_luadocs.hint.patcher_from_dict(input_d)
                self.assertEqual(
                    actual_patcher._selector._section, expected_selector_section
                )
                self.assertEqual(actual_patcher._selector._kind, expected_selector_kind)
                self.assertEqual(
                    actual_patcher._selector._start, expected_selector_start
                )
                self.assertEqual(actual_patcher._selector._stop, expected_selector_stop)
                self.assertIs(type(actual_patcher._modifier), expected_modifier_cls)
                self.assertEqual(actual_patcher._modifier._sep, expected_modifier_sep)


class TestJoinHintPostInit(unittest.TestCase):
    def test_main(self):
        for (
            input_section_nth,
            input_elem_start_idx,
            input_elem_stop_idx,
            input_sep,
            expected_section_nth,
            expected_elem_start_idx,
            expected_elem_stop_idx,
            expected_sep,
        ) in [
            (0, 1, 2, "3", 0, 1, 2, "3"),
            ("0", "1", "2", 3, 0, 1, 2, "3"),
            (None, None, None, "3", None, None, None, "3"),
        ]:
            with self.subTest(
                section_nth=input_section_nth,
                elem_start_idx=input_elem_start_idx,
                elem_stop_idx=input_elem_stop_idx,
                sep=input_sep,
            ):
                actual_hint = sw_luadocs.hint.JoinHint(
                    section_nth=input_section_nth,
                    elem_start_idx=input_elem_start_idx,
                    elem_stop_idx=input_elem_stop_idx,
                    sep=input_sep,
                )
                self.assertEqual(actual_hint.section_nth, expected_section_nth)
                self.assertEqual(actual_hint.elem_start_idx, expected_elem_start_idx)
                self.assertEqual(actual_hint.elem_stop_idx, expected_elem_stop_idx)
                self.assertEqual(actual_hint.sep, expected_sep)


class TestJoinHintApply(unittest.TestCase):
    def test_invalid_type(self):
        hint = sw_luadocs.hint.JoinHint()
        with self.assertRaises(TypeError):
            hint.apply([None])

    def test_invalid_value(self):
        for section_nth, elem_start_idx, elem_stop_idx, sep, flatdoc in [
            (None, None, None, "\n\n", []),
            (
                1,
                1,
                2,
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="body"),
                ],
            ),
        ]:
            with self.subTest(
                section_nth=section_nth,
                elem_start_idx=elem_start_idx,
                elem_stop_idx=elem_stop_idx,
                sep=sep,
                flatdoc=flatdoc,
            ):
                hint = sw_luadocs.hint.JoinHint(
                    section_nth=section_nth,
                    elem_start_idx=elem_start_idx,
                    elem_stop_idx=elem_stop_idx,
                    sep=sep,
                )
                flatdoc = flatdoc[:]
                with self.assertRaises(ValueError):
                    hint.apply(flatdoc)

    def test_main(self):
        for (
            input_section_nth,
            input_elem_start_idx,
            input_elem_stop_idx,
            input_sep,
            input_flatdoc,
            expected_flatdoc,
        ) in [
            (
                None,
                None,
                None,
                "\n\n",
                [sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body")],
                [sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body")],
            ),
            (
                None,
                None,
                None,
                "\n\n",
                [sw_luadocs.flatdoc.FlatElem(txt="c0.0", kind="code")],
                [sw_luadocs.flatdoc.FlatElem(txt="c0.0", kind="code")],
            ),
            (
                None,
                None,
                None,
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                ],
                [sw_luadocs.flatdoc.FlatElem(txt="b0.0\n\nb0.1\n\nb0.2", kind="body")],
            ),
            (
                None,
                None,
                None,
                ", ",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                ],
                [sw_luadocs.flatdoc.FlatElem(txt="b0.0, b0.1, b0.2", kind="body")],
            ),
            (
                None,
                1,
                None,
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1\n\nb0.2", kind="body"),
                ],
            ),
            (
                None,
                None,
                2,
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0\n\nb0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                ],
            ),
            (
                None,
                -3,
                -1,
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0\n\nb0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                ],
            ),
            (
                0,
                None,
                3,
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.6", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.6", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(
                        txt="b0.0\n\nb0.1\n\nb0.2", kind="body"
                    ),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.6", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.6", kind="code"),
                ],
            ),
            (
                0,
                3,
                None,
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.6", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.6", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(
                        txt="c0.3\n\nc0.4\n\nc0.5", kind="code"
                    ),
                    sw_luadocs.flatdoc.FlatElem(txt="h1.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.6", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.6", kind="code"),
                ],
            ),
            (
                1,
                1,
                4,
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.6", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.6", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(
                        txt="b1.1\n\nb1.2\n\nb1.3", kind="body"
                    ),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.6", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.6", kind="code"),
                ],
            ),
            (
                1,
                4,
                None,
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.6", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.6", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(
                        txt="c1.4\n\nc1.5\n\nc1.6", kind="code"
                    ),
                    sw_luadocs.flatdoc.FlatElem(txt="h2.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.6", kind="code"),
                ],
            ),
            (
                2,
                1,
                4,
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.6", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.6", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.6", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(
                        txt="b2.1\n\nb2.2\n\nb2.3", kind="body"
                    ),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.6", kind="code"),
                ],
            ),
            (
                2,
                4,
                None,
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.6", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2.6", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b0.0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b0.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.3", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c0.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h1.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.4", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.5", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1.6", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="h2.0", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2.3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(
                        txt="c2.4\n\nc2.5\n\nc2.6", kind="code"
                    ),
                ],
            ),
        ]:
            with self.subTest(
                section_nth=input_section_nth,
                elem_start_idx=input_elem_start_idx,
                elem_stop_idx=input_elem_stop_idx,
                sep=input_sep,
                flatdoc=input_flatdoc,
            ):
                input_hint = sw_luadocs.hint.JoinHint(
                    section_nth=input_section_nth,
                    elem_start_idx=input_elem_start_idx,
                    elem_stop_idx=input_elem_stop_idx,
                    sep=input_sep,
                )
                input_flatdoc_copy = input_flatdoc[:]
                actual_flatdoc = input_hint.apply(input_flatdoc_copy)
                self.assertEqual(actual_flatdoc, expected_flatdoc)
                self.assertIsNot(actual_flatdoc, input_flatdoc_copy)
                self.assertEqual(input_flatdoc_copy, input_flatdoc)


class TestSplitHintPostInit(unittest.TestCase):
    def test_main(self):
        for (
            input_section_nth,
            input_elem_idx,
            input_txt_pos,
            expected_section_nth,
            expected_elem_idx,
            expected_txt_pos,
        ) in [(0, 1, 2, 0, 1, 2), ("0", "1", "2", 0, 1, 2), (None, 1, 2, None, 1, 2)]:
            with self.subTest(
                section_nth=input_section_nth,
                elem_idx=input_elem_idx,
                txt_pos=input_txt_pos,
            ):
                actual_hint = sw_luadocs.hint.SplitHint(
                    section_nth=input_section_nth,
                    elem_idx=input_elem_idx,
                    txt_pos=input_txt_pos,
                )
                self.assertEqual(actual_hint.section_nth, expected_section_nth)
                self.assertEqual(actual_hint.elem_idx, expected_elem_idx)
                self.assertEqual(actual_hint.txt_pos, expected_txt_pos)


class TestSplitHintApply(unittest.TestCase):
    def test_invalid_type(self):
        hint = sw_luadocs.hint.SplitHint(section_nth=None, elem_idx=0, txt_pos=1)
        with self.assertRaises(TypeError):
            hint.apply([None])

    def test_invalid_index(self):
        for section_nth, elem_idx, txt_pos, flatdoc in [
            (None, 0, 1, []),
            (None, 1, 1, [sw_luadocs.flatdoc.FlatElem(txt="ab", kind="head")]),
            (None, -2, 1, [sw_luadocs.flatdoc.FlatElem(txt="ab", kind="head")]),
            (0, 0, 1, [sw_luadocs.flatdoc.FlatElem(txt="ab", kind="head")]),
            (1, 1, 1, [sw_luadocs.flatdoc.FlatElem(txt="ab", kind="head")]),
            (
                None,
                5,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                None,
                -6,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                0,
                1,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                0,
                -2,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                1,
                2,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                1,
                -3,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                2,
                2,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                2,
                -3,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
        ]:
            with self.subTest(
                section_nth=section_nth,
                elem_idx=elem_idx,
                txt_pos=txt_pos,
                flatdoc=flatdoc,
            ):
                hint = sw_luadocs.hint.SplitHint(
                    section_nth=section_nth, elem_idx=elem_idx, txt_pos=txt_pos
                )
                with self.assertRaises(IndexError):
                    hint.apply(flatdoc)

    def test_main(self):
        for (
            input_section_nth,
            input_elem_idx,
            input_txt_pos,
            input_flatdoc,
            expected_flatdoc,
        ) in [
            (
                None,
                0,
                1,
                [sw_luadocs.flatdoc.FlatElem(txt="ab", kind="head")],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
            ),
            (
                None,
                -1,
                1,
                [sw_luadocs.flatdoc.FlatElem(txt="ab", kind="head")],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
            ),
            (
                None,
                0,
                5,
                [sw_luadocs.flatdoc.FlatElem(txt="123456789", kind="head")],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="12345", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="6789", kind="head"),
                ],
            ),
            (
                1,
                0,
                1,
                [sw_luadocs.flatdoc.FlatElem(txt="ab", kind="head")],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
            ),
            (
                None,
                0,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                None,
                2,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="e", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="f", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                None,
                4,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="i", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="j", kind="code"),
                ],
            ),
            (
                None,
                -5,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                None,
                -3,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="e", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="f", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                None,
                -1,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="i", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="j", kind="code"),
                ],
            ),
            (
                0,
                0,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                0,
                -1,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                1,
                0,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="d", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                1,
                -1,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="e", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="f", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                2,
                0,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="g", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
            ),
            (
                2,
                -1,
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ij", kind="code"),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="cd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ef", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="gh", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="i", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="j", kind="code"),
                ],
            ),
        ]:
            with self.subTest(
                section_nth=input_section_nth,
                elem_idx=input_elem_idx,
                txt_pos=input_txt_pos,
                flatdoc=input_flatdoc,
            ):
                input_hint = sw_luadocs.hint.SplitHint(
                    section_nth=input_section_nth,
                    elem_idx=input_elem_idx,
                    txt_pos=input_txt_pos,
                )
                input_flatdoc_copy = input_flatdoc[:]
                actual_flatdoc = input_hint.apply(input_flatdoc_copy)
                self.assertEqual(actual_flatdoc, expected_flatdoc)
                self.assertIsNot(actual_flatdoc, input_flatdoc_copy)
                self.assertEqual(input_flatdoc_copy, input_flatdoc)


class TestHintFromDict(unittest.TestCase):
    def test_invalid_value(self):
        for d in [{}, {"op": "invalid"}]:
            with self.subTest(d=d):
                with self.assertRaises(ValueError):
                    sw_luadocs.hint.hint_from_dict(d)

    def test_main(self):
        for input_d, expected_hint in [
            ([("op", "join")], sw_luadocs.hint.JoinHint()),
            ({"op": "join"}, sw_luadocs.hint.JoinHint()),
            (
                {
                    "op": "join",
                    "section_nth": 0,
                    "elem_start_idx": 1,
                    "elem_stop_idx": 2,
                    "sep": "3",
                },
                sw_luadocs.hint.JoinHint(
                    section_nth=0, elem_start_idx=1, elem_stop_idx=2, sep="3"
                ),
            ),
            (
                {"op": "split", "section_nth": 0, "elem_idx": 1, "txt_pos": 2},
                sw_luadocs.hint.SplitHint(section_nth=0, elem_idx=1, txt_pos=2),
            ),
        ]:
            with self.subTest(d=input_d):
                input_d_copy = input_d.copy()
                actual_hint = sw_luadocs.hint.hint_from_dict(input_d_copy)
                self.assertEqual(actual_hint, expected_hint)
                self.assertEqual(input_d_copy, input_d)


class TestAsHint(unittest.TestCase):
    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.hint.as_hint(None)

    def test_main(self):
        for input_v, expected_hint in [
            (
                sw_luadocs.hint.JoinHint(
                    section_nth=0, elem_start_idx=1, elem_stop_idx=2, sep="3"
                ),
                sw_luadocs.hint.JoinHint(
                    section_nth=0, elem_start_idx=1, elem_stop_idx=2, sep="3"
                ),
            ),
            (
                sw_luadocs.hint.SplitHint(section_nth=0, elem_idx=1, txt_pos=2),
                sw_luadocs.hint.SplitHint(section_nth=0, elem_idx=1, txt_pos=2),
            ),
            (
                {
                    "op": "join",
                    "section_nth": 0,
                    "elem_start_idx": 1,
                    "elem_stop_idx": 2,
                    "sep": "3",
                },
                sw_luadocs.hint.JoinHint(
                    section_nth=0, elem_start_idx=1, elem_stop_idx=2, sep="3"
                ),
            ),
            (
                {"op": "split", "section_nth": 0, "elem_idx": 1, "txt_pos": 2},
                sw_luadocs.hint.SplitHint(section_nth=0, elem_idx=1, txt_pos=2),
            ),
        ]:
            with self.subTest(v=input_v):
                actual_hint = sw_luadocs.hint.as_hint(input_v)
                self.assertEqual(actual_hint, expected_hint)


class TestApplyHintList(unittest.TestCase):
    def test_invalid_type(self):
        for flatdoc, hint_list in [([None], []), ([], [None])]:
            with self.subTest(flatdoc=flatdoc, hint_list=hint_list):
                with self.assertRaises(TypeError):
                    sw_luadocs.hint.apply_hint_list(flatdoc, hint_list)

    def test_main(self):
        for input_flatdoc, input_hint_list, expected_flatdoc in [
            ([], [], []),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                ],
                [],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                ],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                ],
                [
                    sw_luadocs.hint.JoinHint(
                        section_nth=1, elem_start_idx=1, elem_stop_idx=3, sep=", "
                    )
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1, b2", kind="body"),
                ],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                ],
                [sw_luadocs.hint.SplitHint(section_nth=1, elem_idx=1, txt_pos=1)],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                ],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                ],
                [
                    {
                        "op": "join",
                        "section_nth": 1,
                        "elem_start_idx": 1,
                        "elem_stop_idx": 3,
                        "sep": ", ",
                    },
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1, b2", kind="body"),
                ],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1b2", kind="body"),
                ],
                [
                    sw_luadocs.hint.SplitHint(section_nth=1, elem_idx=1, txt_pos=2),
                    sw_luadocs.hint.JoinHint(
                        section_nth=1, elem_start_idx=1, elem_stop_idx=3, sep="<>"
                    ),
                    sw_luadocs.hint.SplitHint(section_nth=1, elem_idx=1, txt_pos=3),
                ],
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1<", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt=">b2", kind="body"),
                ],
            ),
        ]:
            with self.subTest(flatdoc=input_flatdoc, hint_list=input_hint_list):
                input_flatdoc_copy = input_flatdoc[:]
                actual_flatdoc = sw_luadocs.hint.apply_hint_list(
                    input_flatdoc_copy, input_hint_list
                )
                self.assertEqual(actual_flatdoc, expected_flatdoc)
                self.assertIsNot(actual_flatdoc, input_flatdoc_copy)
                self.assertEqual(input_flatdoc_copy, input_flatdoc)


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
