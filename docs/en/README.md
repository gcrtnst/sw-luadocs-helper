# sw-luadocs-helper
sw-luadocs-helper is a console application that reads Stormworks Lua API documentation and converts it to Markdown.

## Description
sw-luadocs-helper reads Stormworks Lua API documentation using methods such as OCR or data extraction from binaries. It outputs the retrieved documentation as text files written in common markup formats such as Markdown, so you can comfortably read them using familiar applications such as a text editor or browser.

![](https://i.imgur.com/GiOi9kp.png)

Note that sw-luadocs-helper does not read the documentation 100% accurately; running sw-luadocs-helper against all of the Stormworks Lua API documentation will result in a few errors. Therefore, you will have to manually review the output documentation and correct the errors. However, this would be much easier than manually transcribing the document.

## Background
[Stormworks: Build and Rescue](https://store.steampowered.com/app/573090/Stormworks_Build_and_Rescue/) is a sandbox simulation game. It allows players to design vehicles and addons and make them work within a sandbox environment. These vehicles and addons can be programmed using Lua.

In addition to several standard libraries, you can use APIs to control vehicles and addons in Stormworks Lua. These APIs are described in the documentation available in-game. However, this documentation has the following issues:

- The documentation is only available in-game.
  - To read it, you must launch the game each time.
  - You cannot read the documentation when you don't have access to a PC.
- No search function is available.
  - You must manually find the desired description.
- No translation function is available.
  - You must be able to read English. (This may be easy for you reading this, but difficult for me.)

So I wanted to transcribe this documentation into a Markdown file. This would allow the documentation to be read outside of the game, searchable, and easily machine-translated. However, Stormworks is upgraded every two weeks, and manually transcribing the documentation each time was a chore. So I decided to develop an application that could automatically transcribe the documentation.

## Requirements
The following environment is required to use sw-luadocs-helper.
- Windows
  - This application uses the Win32 API and will not work on Mac or Linux.
- Monitor supporting 1920x1080 resolution
  - Required for OCR.

## Installation
First, install the following dependent software. Please select the latest version of any of them.
- [Stormworks: Build and Rescue](https://store.steampowered.com/app/573090/Stormworks_Build_and_Rescue/)
- [Python](https://www.python.org/)
  - `winget install Python.Python.3.X` (X is the minor number)
- [Git](https://git-scm.com/)
  - `winget install Git.Git`
- [Tesseract](https://github.com/tesseract-ocr/tesseract)
  - The Windows installer published by UB Mannheim is available [here](https://github.com/UB-Mannheim/tesseract/wiki).
  - `winget install UB-Mannheim.TesseractOCR`
- [tessdata_best](https://github.com/tesseract-ocr/tessdata_best) / [eng.traineddata](https://github.com/tesseract-ocr/tessdata_best/blob/main/eng.traineddata)
  - Store `eng.traineddata` in Tesseract's tessdata folder.

Next, open a command prompt in an appropriate location and follow these steps to set up sw-luadocs-helper.

```sh
git clone "https://github.com/gcrtnst/sw-luadocs-helper.git"  # clone this repository locally
cd sw-luadocs-helper/src                                      # go to the src/ folder of this repository
python -m venv .venv --upgrade-deps                           # create venv
.venv\Scripts\activate.bat                                    # activate venv
pip install -r requirements.txt                               # install dependent packages
```

Installation is now complete.

From now on, when using sw-luadocs-helper, change directory to the `src/` folder of this repository and activate the virtual environment (`.venv\Scripts\activate.bat`) before running the command.

## Usage
sw-luadocs-helper consists of several subcommands. sw-luadocs-helper can be used to transcribe Lua API documentation by following these steps. Please refer to the documentation for each subcommand for instructions on how to perform each step.
1. Use the `capture` subcommand to capture in-game documentation
    - Documentation for the `capture` subcommand: [usage-capture.md](usage-capture.md)
2. Use the `recognize` subcommand to perform character recognition on the screenshot taken
    - Documentation for the `recognize` subcommand: [usage-recognize.md](usage-recognize.md)
3. Use the `extract` subcommand to retrieve strings from the Stormworks binary based on the recognized strings
    - Documentation for the `extract` subcommand: [usage-extract.md](usage-extract.md)
4. Use the `export` subcommand to convert the retrieved text data to Markdown or other markup format
    - Documentation for the `export` subcommand: [usage-export.md](usage-export.md)

## Development
The following applications are used when developing sw-luadocs-helper. Please select the latest version of any of them.
- [Black](https://github.com/psf/black)
  - All Python code in sw-luadocs-helper is formatted using Black.
  - All configuration are defaults.
  - `pip install black`
- [Flake8](https://github.com/pycqa/flake8)
  - Avoid warnings for all Python code in sw-luadocs-helper.
  - The configuration file is located in `src/.flake8` in this repository.
  - `pip install flake8`

## License
For the license of sw-luadocs-helper, please refer to the [LICENSE](../../LICENSE) file stored in the root folder of this repository.
