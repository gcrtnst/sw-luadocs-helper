# `extract` subcommand
This page describes how to use the `extract` subcommand.

## Synopsis
```
python -m sw_luadocs extract [-h] [--stormworks32-exe STORMWORKS32_EXE] [--stormworks64-exe STORMWORKS64_EXE] recognize_path extract_path
```

## Description
The `extract` subcommand replaces each string output from the `recognize` subcommand with a similar string taken from the Stormworks binary. This can compensate for OCR inaccuracies.

The following image shows an example of text data before and after processing with the `extract` subcommand. The left image is before processing and the right image is after processing. In the text data before processing, there are some misrecognitions such as "1" being mistaken for "l", whereas in the text data after processing, these misrecognitions are corrected appropriately.

![](https://i.imgur.com/dqRFsTD.png)

To use the `extract` subcommand, you must first prepare the following:
- Install sw-luadocs-helper according to [README.md](README.md#Installation), if not already installed.
- Prepare the text data by executing the `recognize` subcommand first.
  - See [usage-recognize.md](usage-recognize.md) for usage of the `recognize` subcommand.

After the above preparations, execute the `extract` subcommand. Specify the arguments as follows:
- Specify input and output text files as positional arguments.
  - The input text file should be the output from the `recognize` subcommand.
  - Note that if you specify a folder instead of a file for both input and output, the application will batch process files directly under the input folder and store the results directly under the output folder.

Below are example commands.
```sh
# Preparation
cd src/                     # go to the src/ folder of this repository
.venv\Scripts\activate.bat  # activate venv

# Process Addon.ocr.txt and output the result to Addon.ext.txt
python -m sw_luadocs extract Addon.ocr.txt Addon.ext.txt

# Batch process files in the Input/ folder and output the results to the Output/ folder.
python -m sw_luadocs extract Input/ Output/
```

The `extract` subcommand automatically corrects most misrecognitions, but it is not perfect. Occasionally, it will select and output incorrect text data from Stormworks binaries. You should manually review the text file output from the `extract` subcommand and correct the misrecognitions as necessary.

After working with the `extract` subcommand, the next step is to convert the text data to Markdown or other markup format with the `export` subcommand, see [usage-export.md](usage-export.md).

The `extract` subcommand will automatically detect the location of the Stormworks binaries installed on your system. If the automatic detection fails, an exception will be raised. In this case, please follow the steps below.
- If you have not yet installed Stormworks, follow the instructions in [README.md](README.md#Installation).
- If you have already installed Stormworks and still get the above exception, use the `--stormworks32-exe` and `--stormworks64-exe` arguments to specify the location of the Stormworks binaries.
  - For `--stormworks32-exe`, specify `stormworks.exe` (the 32-bit version of the Stormworks binary).
  - For `--stormworks64-exe`, specify `stormworks64.exe` (the 64-bit version of the Stormworks binary).
  - Both `--stormworks32-exe` and `--stormworks64-exe` must be specified. Otherwise, it will not work.

## Command Line Options
### Positional Arguments
- `recognize_path`: Location of the text file output from the `recognize` subcommand
  - If a file is specified, the application processes that file.
  - If a folder is specified, the application processes all files directly under that folder.
  - Enter a text file in flatdoc format, see the flatdoc chapter in [usage-export.md](usage-export.md#flatdoc) for more information about flatdoc.
- `extract_path`: Output destination for text files
  - If a file is specified in `recognize_path`, this argument must also be a file.
  - If a folder is specified in `recognize_path`, this argument must also be a folder. Files will be output directly under this folder. The name of each output file will be the same as the name of the corresponding input file.
  - The application outputs a text file in flatdoc format, see the flatdoc chapter in [usage-export.md](usage-export.md#flatdoc) for more information about flatdoc.

### Options
- `-h`: Show help message and exit
- `--stormworks32-exe`: 32-bit Stormworks Binary Locations
  - If not specified, it will be auto-detected.
  - Both the 32-bit and 64-bit Stormworks binaries are required. Only one will not work.
- `--stormworks64-exe`: 64-bit Stormworks Binary Locations
  - If not specified, it will be auto-detected.
  - Both the 32-bit and 64-bit Stormworks binaries are required. Only one will not work.
