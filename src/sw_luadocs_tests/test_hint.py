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
                actual_joinhint = sw_luadocs.hint.JoinHint(
                    section_nth=input_section_nth,
                    elem_start_idx=input_elem_start_idx,
                    elem_stop_idx=input_elem_stop_idx,
                    sep=input_sep,
                )
                self.assertEqual(actual_joinhint.section_nth, expected_section_nth)
                self.assertEqual(
                    actual_joinhint.elem_start_idx, expected_elem_start_idx
                )
                self.assertEqual(actual_joinhint.elem_stop_idx, expected_elem_stop_idx)
                self.assertEqual(actual_joinhint.sep, expected_sep)


class TestJoinHintApply(unittest.TestCase):
    def test_invalid_type(self):
        joinhint = sw_luadocs.hint.JoinHint()
        with self.assertRaises(TypeError):
            joinhint.apply([None])

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
                joinhint = sw_luadocs.hint.JoinHint(
                    section_nth=section_nth,
                    elem_start_idx=elem_start_idx,
                    elem_stop_idx=elem_stop_idx,
                    sep=sep,
                )
                flatdoc = flatdoc[:]
                with self.assertRaises(ValueError):
                    joinhint.apply(flatdoc)

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
                input_joinhint = sw_luadocs.hint.JoinHint(
                    section_nth=input_section_nth,
                    elem_start_idx=input_elem_start_idx,
                    elem_stop_idx=input_elem_stop_idx,
                    sep=input_sep,
                )
                input_flatdoc_copy = input_flatdoc[:]
                actual_flatdoc = input_joinhint.apply(input_flatdoc_copy)
                self.assertEqual(actual_flatdoc, expected_flatdoc)
                self.assertEqual(input_flatdoc_copy, input_flatdoc)


class TestSplitHintPostInit(unittest.TestCase):
    def test_main(self):
        for (
            input_section_nth,
            input_elem_idx,
            input_txt_len,
            expected_section_nth,
            expected_elem_idx,
            expected_txt_len,
        ) in [(0, 1, 2, 0, 1, 2), ("0", "1", "2", 0, 1, 2), (None, 1, 2, None, 1, 2)]:
            with self.subTest(
                section_nth=input_section_nth,
                elem_idx=input_elem_idx,
                txt_len=input_txt_len,
            ):
                actual_hint = sw_luadocs.hint.SplitHint(
                    section_nth=input_section_nth,
                    elem_idx=input_elem_idx,
                    txt_len=input_txt_len,
                )
                self.assertEqual(actual_hint.section_nth, expected_section_nth)
                self.assertEqual(actual_hint.elem_idx, expected_elem_idx)
                self.assertEqual(actual_hint.txt_len, expected_txt_len)
