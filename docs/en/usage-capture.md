# `capture` subcommand
This page describes how to use the `capture` subcommand.

## Synopsis
```
python -m sw_luadocs capture [-h] -c CONFIG capture_file
```

## Description
The `capture` subcommand takes a screenshot of the Stormworks Lua API documentation. It captures the entire document, not just the displayed area, by automatically scrolling through the document.

Below is an example of a screenshot taken.

![](https://i.imgur.com/fOfsdKn.png)

To use the `capture` subcommand, you must first prepare the following:
- Install sw-luadocs-helper according to [README.md](README.md#Installation), if not already installed.
- In Stormworks settings, set Window Mode to Fullscreen and Resolution to 1920 x 1080.
- Please start Stormworks beforehand and display the document you wish to capture.

After the above preparations, execute the `capture` subcommand. Specify the arguments as follows:
- Specify a configuration file as the `-c CONFIG` option.
  - The configuration files are located in the `cfg/` folder of this repository.
  - Specify `sw_luadocs_addon.toml` for Addon Lua documentation or `sw_luadocs_vehicle.toml` for Vehicle Lua documentation.
- Specify the destination file for screenshots taken as the positional argument.

Below are example commands.
```sh
# Preparation
cd src/                     # go to the src/ folder of this repository
.venv\Scripts\activate.bat  # activate venv

# Capture the Addon Lua documentation and output the result to Addon.png
python -m sw_luadocs capture -c ../cfg/sw_luadocs_addon.toml Addon.png

# Capture the Vehicle Lua documentation and output the result to Vehicle.png
python -m sw_luadocs capture -c ../cfg/sw_luadocs_vehicle.toml Vehicle.png
```

The `capture` subcommand works as follows:
1. Activate the Stormworks window.
2. Scroll to the top of the document.
3. Take a screenshot.
4. Scroll down a bit.
5. Repeat steps 3 and 4 until the application reaches the bottom of the document.
6. Minimize the Stormworks window.
7. Combines all screenshots taken and outputs them to a file.

Do not touch the mouse or keyboard while the `capture` subcommand is executing. Any operation during execution may cause the screenshot to fail.

After working with the `capture` subcommand, the next step is character recognition with the `recognize` subcommand, see [usage-recognize.md](usage-recognize.md).

## Command Line Options
### Positional Arguments
- `capture_file`: Destination file for screenshots taken
  - It uses Pillow to save images. See `python -m PIL` for a list of supported image formats.

### Options
- `-h`: Show help message and exit
- `-c CONFIG`, `--config CONFIG`: Configuration file in TOML format (required)
  - Specify the files stored in the `cfg/` folder of this repository. `sw_luadocs_addon.toml` is for Addon Lua documentation and `sw_luadocs_vehicle.toml` is for Vehicle Lua documentation.
  - See the [Configuration File](#Configuration-File) chapter for a list of configuration items used.

## Configuration File
The `capture` subcommand uses the following configuration items:

```toml
[capture]
screen_width = 1920
screen_height = 1080

scroll_x = 960
scroll_y = 540
scroll_init_delta = 122880
scroll_down_delta = -360
scroll_threshold = 0

capture_area_x = 312
capture_area_y = 226
capture_area_w = 1285
capture_area_h = 763
capture_template_ratio = 0.25

activate_delay = 5
scroll_mouse_delay = 0.1
scroll_smooth_delay = 3
```

- `screen_width`, `screen_height`: Screen resolution
  - If Stormworks' screen resolution does not match this configuration item, an exception will be raised.
  - If you change this configuration item, consider modifying other configuration items related to coordinates.
- `scroll_x`, `scroll_y`: Mouse cursor position when scrolling
  - When scrolling through a document, the application moves the mouse cursor to this position and then simulates the rotation of the mouse wheel.
- `scroll_init_delta`: The amount of mouse wheel rotation when scrolling to the top of the document.
  - Specify a positive number.
  - The amount of rotation for one notch of the mouse wheel is 120.
- `scroll_down_delta`: The amount of mouse wheel rotation when scrolling down a document one time.
  - Specify a negative number.
  - The amount of rotation for one notch of the mouse wheel is 120.
- `scroll_threshold`: Threshold for determining if scrolling has reached the bottom
  - If the number of pixels actually scrolled after rotating the mouse wheel is less than this number, the scrolling is considered to have reached the bottom.
- `capture_area_x`, `capture_area_y`, `capture_area_w`, `capture_area_h`: Screen capture area
  - Specify the area where the document is displayed.
  - X coordinate, Y coordinate, width, and height, respectively.
- `capture_template_ratio`: Ratio of area used for template matching
  - To calculate the number of pixels scrolled, the application crops the image by this ratio from the pre-scroll image and performs template matching with the post-scroll image.
- `activate_delay`: Sleep time from activation of the Stormworks window until the game screen appears
- `scroll_mouse_delay`: Sleep time after moving the mouse cursor until it is recognized by Stormworks
- `scroll_smooth_delay`: Sleep time from mouse wheel rotation to end of scrolling animation
