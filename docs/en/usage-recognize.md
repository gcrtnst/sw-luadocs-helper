# `recognize` subcommand
This page describes how to use the `recognize` subcommand.

## Synopsis
```
python -m sw_luadocs recognize [-h] -c CONFIG [--tesseract-exe TESSERACT_EXE] capture_path recognize_path
```

## Description
The `recognize` subcommand performs the following operations on screenshots taken with the `capture` subcommand:
- Perform character recognition on screenshots and convert to text data.
- Classify recognized strings into one of the following types: headline, body, code

The following is an example of an actual output text file. The classified type is listed at the beginning of each line, followed by the recognized string. (See the flatdoc chapter of [usage-export.md](usage-export.md#flatdoc) for the format of this text file.)
![](https://i.imgur.com/PlaDsP6.png)

To use the `recognize` subcommand, you must first prepare the following:
- Install sw-luadocs-helper according to [README.md](README.md#Installation), if not already installed.
- Take a screenshot by executing the `capture` subcommand first.
  - See [usage-capture.md](usage-capture.md) for usage of the `capture` subcommand.

After the above preparations, execute the `recognize` subcommand. Specify the arguments as follows:
- Specify a configuration file with the `-c CONFIG` option.
  - The configuration files are located in the `cfg/` folder of this repository.
  - Specify `sw_luadocs_addon.toml` for Addon Lua documentation or `sw_luadocs_vehicle.toml` for Vehicle Lua documentation.
- Specify the screenshot file to be input and the text file to be output as the positional argument.
  - The screenshot file to be entered should be one taken with the `capture` subcommand.
  - Note that if you specify a folder instead of a file for both input and output, the application will batch process files directly under the input folder and store the results directly under the output folder.

Below are example commands.
```sh
# Preparation
cd src/                     # go to the src/ folder of this repository
.venv\Scripts\activate.bat  # activate venv

# Process Addon.png as a screenshot of Addon Lua and output the result to Addon.ocr.txt
python -m sw_luadocs recognize -c ../cfg/sw_luadocs_addon.toml Addon.png Addon.ocr.txt

# Batch process files in the Input folder as Addon Lua screenshots and output the results to the Output folder
python -m sw_luadocs recognize -c ../cfg/sw_luadocs_addon.toml Input/ Output/

# Process Vehicle.png as a screenshot of Vehicle Lua and output the result to Vehicle.ocr.txt
python -m sw_luadocs recognize -c ../cfg/sw_luadocs_vehicle.toml Vehicle.png Vehicle.ocr.txt
```

After working with the `recognize` subcommand, the next step is to automatically correct errors with the `extract` subcommand, see [usage-extract.md](usage-extract.md).

If you get an exception `pytesseract.pytesseract.TesseractNotFoundError` at runtime, please follow the steps below.
- If you have not yet installed Tesseract, follow the instructions in [README.md](README.md#Installation).
- If you have already installed Tesseract and still get the above exception, manually specify the location of `tesseract.exe` with the `--tesseract-exe` argument.

## Command Line Options
### Positional Arguments
- `capture_path`: Location of screenshots taken with the `capture` subcommand.
  - If a file is specified, the application processes that file.
  - If a folder is specified, the application processes all files directly under that folder.
  - It uses Pillow to save images. See `python -m PIL` for a list of supported image formats.
- `recognize_path`: Output destination for text files
  - If a file is specified in `capture_path`, this argument must also be a file.
  - If a folder is specified in `capture_path`, this argument must also be a folder. Files will be output directly under this folder. Each output file is renamed from the input file name with `.txt` extension.
  - The application outputs a text file in flatdoc format, see the flatdoc chapter in [usage-export.md](usage-export.md#flatdoc) for more information about flatdoc.

### Options
- `-h`: Show help message and exit
- `-c CONFIG`, `--config CONFIG`: Configuration file in TOML format (required)
  - Specify the files stored in the `cfg/` folder of this repository. `sw_luadocs_addon.toml` is for Addon Lua documentation and `sw_luadocs_vehicle.toml` is for Vehicle Lua documentation.
  - See the [Configuration File](#Configuration-File) chapter for a list of configuration items used.
- `--tesseract-exe TESSERACT_EXE`：Location of `tesseract.exe`
  - If not specified, it will be detected automatically.

## Configuration File
The `recognize` subcommand uses the following configuration items:

```toml
[recognize]
preprocess_scale = 2
tesseract_lang = "eng"
body_line_h = 21
code_thresh_x = 9
code_base_x = 14
code_indent_w = 38
code_line_h = 16.5
```

- `preprocess_scale`: Magnification in image preprocessing
  - The application resizes the image according to this configuration item before using Tesseract for character recognition.
  - A value greater than 1 means expansion, and a value less than 1 means contraction.
  - According to [tessdoc](https://tesseract-ocr.github.io/tessdoc/ImproveQuality.html#rescaling), Tesseract works best on images which have a DPI of at least 300 dpi.
- `tesseract_lang`: Tesseract language code string
- `body_line_h`: Height per line of text (in pixels)
- `code_thresh_x`: X coordinate threshold for classifying whether a recognized string is a code or not
  - If the left edge of the recognized string area is to the right of the X coordinate specified in this configuration item, the string is classified as a code.
- `code_base_x`: X coordinate of left end of code
  - The indentation level is recognized by calculating the difference between the X coordinate of the recognized string area and the X coordinate of this configuration item.
- `code_indent_w`: Width of tab character in code (in pixels)
- `code_line_h`: Height per line of code (in pixels)

The following image visually shows coordinate-related configuration items.

![](https://i.imgur.com/NRopEaE.png)
