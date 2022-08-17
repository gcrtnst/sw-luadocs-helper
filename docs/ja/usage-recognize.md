# `recognize` サブコマンド
このページでは `recognize` サブコマンドの使い方を説明します。

## 概要
```
python -m sw_luadocs recognize [-h] -c CONFIG [--tesseract-exe TESSERACT_EXE] capture_path recognize_path
```

## 説明
`recognize` サブコマンドは、`capture` サブコマンドで撮影されたスクリーンショットに対して以下の処理を実施します。
- スクリーンショット内の文章に対して文字認識を行い、テキストデータにする。
- 認識した文章を次のいずれかの種類に分類する：見出し、本文、コード

以下は実際に出力されたテキストファイルの例です。
![recognize サブコマンドから出力されたテキストファイルの例](https://i.imgur.com/PlaDsP6.png)

`recognize` サブコマンドを実行するには、まず下記の準備作業が必要です。
- インストールがまだの場合は、[README.md](README.md) に従いインストールを済ませてください。
- 先に `capture` サブコマンドを実行して、スクリーンショットを用意してください。
  - `capture` サブコマンドの使い方は [usage-capture.md](usage-capture.md) を参照ください。

準備が出来たら、`recognize` サブコマンドを実行します。引数は以下の通りに設定してください。
- `-c CONFIG` オプションで設定ファイルを指定してください。
  - 設定ファイルは本リポジトリの `cfg/` フォルダにあります。
  - Addon Lua のヘルプを処理する場合は `sw_luadocs_addon.toml` を、Vehicle Lua のヘルプを処理する場合は `sw_luadocs_vehicle.toml` を指定してください。
- 位置引数で、入力するスクリーンショットファイルと、出力先のテキストファイルを指定してください。
  - 入力するスクリーンショットファイルは、`capture` サブコマンドで撮影したものを使用してください。
  - なお、入出力の両方にファイルではなくフォルダを指定すると、入力フォルダ直下のファイルを一括処理して、結果を出力フォルダ直下に格納します。各出力ファイルの名前は、入力ファイルの名前を拡張子 `.txt` でリネームしたものとなります。

以下はコマンド例です。
```sh
# 準備
cd src/                     # 本リポジトリの src/ フォルダに移動
.venv/Scripts/activate.bat  # 仮想環境の有効化

# Addon.png に格納されている Addon Lua ヘルプのスクリーンショットを処理して、結果を Addon.ocr.txt に出力する場合
python -m sw_luadocs recognize -c ../cfg/sw_luadocs_addon.toml Addon.png Addon.ocr.txt

# Input/ に格納されている Addon Lua ヘルプのスクリーンショットを一括処理して、結果を Output/ に出力する場合
python -m sw_luadocs recognize -c ../cfg/sw_luadocs_addon.toml Input/ Output/

# Vehicle.png に格納されている Vehicle Lua ヘルプのスクリーンショットを処理して、結果を Vehicle.ocr.txt に出力する場合
python -m sw_luadocs recognize -c ../cfg/sw_luadocs_vehicle.toml Vehicle.png Vehicle.ocr.txt
```

もし、実行時に `pytesseract.pytesseract.TesseractNotFoundError` という例外が発生した場合は、以下の手順で対処してください。
- まだ Tesseract-OCR をインストールしていない場合は、[README.md](README.md) に従ってインストールしてください。
- Tesseract-OCR を既にインストールしているにもかかわらず上記の例外が発生する場合は、`--tesseract-exe` 引数で `tesseract` コマンドの場所を手動で指定してください。

## コマンドラインオプション
### 位置引数
- `capture_path`：`capture` サブコマンドで撮影されたスクリーンショットの格納場所
  - ファイルが指定された場合は、そのファイルを処理します。
  - フォルダが指定された場合は、そのフォルダの直下にあるファイルを全て処理します。
- `recognize_path`：処理結果の出力先
  - `capture_path` でファイルを指定した場合は、この項目もファイルを指定してください。
  - `capture_path` でフォルダを指定した場合は、この項目もフォルダを指定してください。

### オプション
- `-h`：ヘルプメッセージを出力して終了
- `-c CONFIG`, `--config CONFIG`：設定ファイル（必須）
- `--tesseract-exe TESSERACT_EXE`：`tesseract` 実行可能ファイルの場所
