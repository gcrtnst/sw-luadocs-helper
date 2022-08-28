# `recognize` サブコマンド
このページでは `recognize` サブコマンドの使い方を説明します。

## 概要
```
python -m sw_luadocs recognize [-h] -c CONFIG [--tesseract-exe TESSERACT_EXE] capture_path recognize_path
```

## 説明
`recognize` サブコマンドは、`capture` サブコマンドで撮影されたスクリーンショットに対して以下の処理を実施します。
- スクリーンショット内の文章に対して文字認識を行い、テキストデータにする。
- 認識した文字列を次のいずれかの種類に分類する：見出し、本文、コード

以下は実際に出力されたテキストファイルの例です。各行の先頭に分類された種類が記載され、その後に認識した文字列が記載されています。（このテキストファイルの形式については [usage-export.md](usage-export.md#flatdoc) の flatdoc 章を参照ください）
![](https://i.imgur.com/PlaDsP6.png)

`recognize` サブコマンドを実行するには、まず下記の準備作業が必要です。
- インストールがまだの場合は、[README.md](README.md#インストール) に従いインストールを済ませてください。
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

# Addon.png を Addon Lua のスクリーンショットとして処理して、結果を Addon.ocr.txt に出力する場合
python -m sw_luadocs recognize -c ../cfg/sw_luadocs_addon.toml Addon.png Addon.ocr.txt

# Input フォルダに格納されているファイルを Addon Lua のスクリーンショットとして一括処理して、結果を Output フォルダに出力する場合
python -m sw_luadocs recognize -c ../cfg/sw_luadocs_addon.toml Input/ Output/

# Vehicle.png を Vehicle Lua のスクリーンショットとして処理して、結果を Vehicle.ocr.txt に出力する場合
python -m sw_luadocs recognize -c ../cfg/sw_luadocs_vehicle.toml Vehicle.png Vehicle.ocr.txt
```

`recognize` サブコマンドでの作業が完了したら、次は `extract` サブコマンドで誤記の自動修正を行います。[usage-extract.md](usage-extract.md) を参照ください。

もし、実行時に `pytesseract.pytesseract.TesseractNotFoundError` という例外が発生した場合は、以下の手順で対処してください。
- まだ Tesseract をインストールしていない場合は、[README.md](README.md) に従ってインストールしてください。
- Tesseract を既にインストールしているにもかかわらず上記の例外が発生する場合は、`--tesseract-exe` 引数で `tesseract.exe` の場所を手動で指定してください。

## コマンドラインオプション
### 位置引数
- `capture_path`：`capture` サブコマンドで撮影されたスクリーンショットの格納場所
  - `capture` サブコマンドで撮影したスクリーンショットを指定してください。
  - ファイルが指定された場合は、そのファイルを処理します。
  - フォルダが指定された場合は、そのフォルダの直下にあるファイルを全て処理します。
  - Pillow を使用して画像を読み込みます。サポートされている画像フォーマットの一覧は `python -m PIL` を参照ください。
- `recognize_path`：テキストファイルの出力先
  - `capture_path` でファイルを指定した場合は、この引数もファイルを指定してください。
  - `capture_path` でフォルダを指定した場合は、この引数もフォルダを指定してください。このフォルダの直下にファイルを出力します。各出力ファイルの名前は、入力ファイルの名前を拡張子 `.txt` でリネームしたものとなります。
  - flatdoc 形式のテキストファイルが出力されます。flatdoc については [usage-export.md](usage-export.md#flatdoc) の flatdoc 章を参照ください。

### オプション
- `-h`：ヘルプメッセージを出力して終了
- `-c CONFIG`, `--config CONFIG`：TOML 形式の設定ファイル（必須）
  - 本リポジトリの `cfg/` フォルダに格納されているファイルを指定してください。`sw_luadocs_addon.toml` は Addon Lua のヘルプ用、`sw_luadocs_vehicle.toml` は Vehicle Lua のヘルプ用です。
  - 使用する設定項目の一覧は[設定ファイル](#設定ファイル)の章を参照ください。
- `--tesseract-exe TESSERACT_EXE`：`tesseract.exe` の場所
  - 未指定の場合は自動検出します。

## 設定ファイル
`recognize` サブコマンドは以下の設定項目を使用します。

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

- `preprocess_scale`：画像前処理における拡大率
  - Tesseract を使って文字認識をする前に、この設定項目に従い画像をリサイズします。
  - 1 より値が大きいと拡大され、小さいと縮小されます。
  - [tessdoc](https://tesseract-ocr.github.io/tessdoc/ImproveQuality.html#rescaling) によると、Tesseract は 300dpi 以上の DPI を持つ画像に対して最適に動作します。
- `tesseract_lang`：Tesseract の言語コード文字列
- `body_line_h`：本文1行あたりの高さ（ピクセル単位）
- `code_thresh_x`：認識した文字列がコードかどうか判定するための X 座標閾値
  - 認識した文字列領域の左端が、この設定項目で指定した X 座標より右にある場合、その文字列はコードであると判定します。
- `code_base_x`：コードの左端 X 座標
  - 認識した文字列領域の X 座標と、この設定項目の X 座標の差を計算することで、インデントレベルを導出します。
- `code_indent_w`：コードにおけるタブ文字の幅（ピクセル単位）
- `code_line_h`：コード一行あたりの高さ（ピクセル単位）

以下の画像は、座標関連の設定項目を視覚的に表したものです。

![](https://i.imgur.com/NRopEaE.png)
