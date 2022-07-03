import sw_luadocs.flatdoc
import sw_luadocs.hint
import unittest


class TestGetSection(unittest.TestCase):
    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.hint.get_section([None], 0)

    def test_invalid_index(self):
        for flatdoc, sect_nth in [
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
            with self.subTest(flatdoc=flatdoc, sect_nth=sect_nth):
                with self.assertRaises(IndexError):
                    sw_luadocs.hint.get_section(flatdoc, sect_nth)

    def test_main(self):
        for input_flatdoc, input_sect_nth, expected_flatsect in [
            ([], 0, []),
            ([], -1, []),
            ([], "0", []),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                ],
                0,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                ],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                ],
                -1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                ],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
                0,
                [],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
                -2,
                [],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
                1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
                -1,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
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
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                ],
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
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                ],
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
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
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
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="code"),
                ],
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
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                ],
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
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 0", kind="code"),
                ],
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
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                ],
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
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 1", kind="head"),
                ],
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
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="code"),
                ],
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
                [
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="sect 2", kind="code"),
                ],
            ),
        ]:
            with self.subTest(flatdoc=input_flatdoc, sect_nth=input_sect_nth):
                actual_flatsect = sw_luadocs.hint.get_section(
                    input_flatdoc, input_sect_nth
                )
                self.assertEqual(actual_flatsect, expected_flatsect)
