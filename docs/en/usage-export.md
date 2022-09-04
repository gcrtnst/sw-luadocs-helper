# `export` subcommand
This page describes how to use the `export` subcommand.

## Synopsis
```
python -m sw_luadocs export [-h] [-f FORMAT] [--encoding ENCODING] [--newline NEWLINE] load_path save_path
```

## Description
The `export` subcommand converts the text file output from the `extract` subcommand to Markdown or other markup format.

The text file output from the `extract` subcommand is in sw-luadocs-helper's own format, but you can convert it to a common markup format by using the `export` subcommand. This allows you to process the text data in familiar applications, such as converting it to HTML or displaying it in a readable format.

The following image shows an example of a text file before and after conversion by the `export` subcommand. On the left is before conversion and on the right is after conversion.

![](https://i.imgur.com/jhQdxd2.png)

To use the `export` subcommand, you must first prepare the following:
- Install sw-luadocs-helper according to [README.md](README.md#Installation), if not already installed.

After the above preparations, execute the `export` subcommand. Specify the arguments as follows:
- Specify the markup format with the `-f FORMAT` option.
  - Available markup formats are `markdown` or `wikiwiki`.
  - `wikiwiki` is the format used by [WikiWiki](https://wikiwiki.jp/), a free rental wiki service primarily in Japan. `wikiwiki` is similar to the [PukiWiki](https://pukiwiki.osdn.jp/) format, but assumes that the [code plugin](https://wikiwiki.jp/sample/Manual/A-D#sd91fd21) is installed.
  - The default is `markdown`.
- Specify input and output text files as positional arguments.
  - The input text file should be in flatdoc format.
    - The text files output from the `recognize` and `extract` subcommands are in flatdoc format.
    - See the [flatdoc](#flatdoc) chapter for more information on the flatdoc format.
  - Note that if you specify a folder instead of a file for both input and output, the application will batch process files directly under the input folder and store the results directly under the output folder.

Below are example commands.
```sh
# Preparation
cd src/                     # go to the src/ folder of this repository
.venv\Scripts\activate.bat  # activate venv

# Convert Addon.txt to Markdown format and output the result to Addon.md
python -m sw_luadocs export Addon.txt Addon.md

# Convert Addon.txt to WikiWiki format and output the result to WikiWiki.txt
python -m sw_luadocs export -f wikiwiki Addon.txt WikiWiki.txt

# Convert all files in the Input/ folder to Markdown format and output the results to the Output/ folder.
python -m sw_luadocs export Input/ Output/

# Convert all files in the Input/ folder to WikiWiki format and output the results to the Output/ folder.
python -m sw_luadocs export -f wikiwiki Input/ Output/
```

The conversion process with the `export` subcommand is simple and does not perform escaping of inline HTML or special symbols. This may result in unintended markup depending on the input text data. You should manually review the text file output from the `export` subcommand and modify the markup as necessary.

## Command Line Options
### Positional Arguments
- `load_path`: Input file location
  - If a file is specified, the application processes that file.
  - If a folder is specified, the application processes all files directly under that folder.
  - Enter a text file in flatdoc format, see the [flatdoc](#flatdoc) chapter for more information about flatdoc.
- `save_path`: Output file location
  - If a file is specified in `load_path`, this argument must also be a file.
  - If a folder is specified in `load_path`, this argument must also be a folder. Files will be output directly under this folder. The name of each output file is the name of the input file renamed with the following extension.
    - If the markup format is `markdown`, the extension is `.md`.
    - If the markup format is `wikiwiki`, the extension is `.txt`.
  - The application outputs a text file in flatdoc format, see the [flatdoc](#flatdoc) chapter for more information about flatdoc.

### Options
- `-f FORMAT`, `--format FORMAT`: Target markup format
  - Available markup formats are `markdown` or `wikiwiki`.
  - The default is `markdown`.
- `--encoding ENCODING`: Output file encoding
  - See [the Python documentation](https://docs.python.org/3/library/codecs.html#standard-encodings) for a list of available encodings.
  - The default is `utf-8`.
- `--newline NEWLINE`: Output file newline code
  - Available newline codes are `LF`, `CR`, or `CRLF`.
  - The default is `LF`.

## flatdoc
flatdoc is a markup format used in sw-luadocs-helper. The name comes from the fact that, unlike HTML, Markdown, and other common markup formats, it cannot handle hierarchical structures and can only express flat text. It can represent Stormworks Lua API documentation, but is designed to be simple enough to be easily parsed programmatically.

Below is an example of text data in flatdoc format.
```
head This is a headline
body This is the first body
body This is the first line of the second body
.... This is the second line of the second body
code This is the first line of code
.... This is the second line of code
```

Text data in flatdoc format must be in UTF-8 encoding with LF line breaks.

Each line consists of the following strings:
- 1st to 4th characters: string representing the element type
  - `head`, `body`, `code`, or `....`
  - `....` denotes a continuation of an element from the previous line.
- 5th character: space character
- 6th and after: text of the element

The text data in the example above represents text with the following four elements:
- heading element with the text `This is a headline`
- body element with the text `This is the first body`
- body element with two lines of text: `This is the first line of the second body` and `This is the second line of the second body`
- code element with two lines of text: `This is the first line of code` and `This is the second line of code`

The text data in the example above can be converted to Markdown with the `export` subcommand as follows:

``````markdown
# This is a headline

This is the first body

This is the first line of the second body
This is the second line of the second body

```lua
This is the first line of code
This is the second line of code
```
``````
