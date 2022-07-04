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


class TestJoinHintPostInit(unittest.TestCase):
    def test_main(self):
        for (
            input_section_nth,
            input_start_idx,
            input_stop_idx,
            input_sep,
            expected_section_nth,
            expected_start_idx,
            expected_stop_idx,
            expected_sep,
        ) in [
            (0, 1, 2, "3", 0, 1, 2, "3"),
            ("0", "1", "2", 3, 0, 1, 2, "3"),
            (None, None, None, "3", None, None, None, "3"),
        ]:
            with self.subTest(
                section_nth=input_section_nth,
                start_idx=input_start_idx,
                stop_idx=input_stop_idx,
                sep=input_sep,
            ):
                actual_joinhint = sw_luadocs.hint.JoinHint(
                    section_nth=input_section_nth,
                    start_idx=input_start_idx,
                    stop_idx=input_stop_idx,
                    sep=input_sep,
                )
                self.assertEqual(actual_joinhint.section_nth, expected_section_nth)
                self.assertEqual(actual_joinhint.start_idx, expected_start_idx)
                self.assertEqual(actual_joinhint.stop_idx, expected_stop_idx)
                self.assertEqual(actual_joinhint.sep, expected_sep)
