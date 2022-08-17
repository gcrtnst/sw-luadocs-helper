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

準備が出来たら、`recognize` コマンドを実行します。引数は以下の通りに設定してください。
- `-c CONFIG` オプションで設定ファイルを指定してください。設定ファイルは本リポジトリの `cfg/` ディレクトリにあります。Addon Lua のヘルプを処理する場合は `sw_luadocs_addon.toml` を、Vehicle Lua のヘルプを処理する場合は `sw_luadocs_vehicle.toml` を指定してください。
- `--tesseract-exe TESSERACT_EXE` オプションで `tesseract` コマンドの場所を指定できます。通常は自動的に検出するため、明示的に指定する必要はありませんが、もし `tesseract` コマンドの場所が不明であるという例外が発生した場合は指定してください。
- 位置引数で、`capture` コマンドで撮影したスクリーンショットのファイルと、出力先のテキストファイルを指定してください。

以下はコマンド例です。
```sh
# 準備
cd src/                     # 本リポジトリの src/ ディレクトリに移動
.venv/Scripts/activate.bat  # 仮想環境の有効化

# Addon.png に保存されている、Addon Lua ヘルプのスクリーンショットを文字認識して、結果を Addon.ocr.txt に保存する場合
python -m sw_luadocs -c ..\cfg\sw_luadocs_addon.toml Addon.png Addon.ocr.txt

# Vehicle.png に保存されている、Vehicle Lua ヘルプのスクリーンショットを文字認識して、結果を Vehicle.ocr.txt に保存する場合
python -m sw_luadocs -c ..\cfg\sw_luadocs_vehicle.toml Vehicle.png Vehicle.ocr.txt
```
