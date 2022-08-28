# `extract` サブコマンド
このページでは `extract` サブコマンドの使い方を説明します。

## 概要
```
python -m sw_luadocs extract [-h] [--stormworks32-exe STORMWORKS32_EXE] [--stormworks64-exe STORMWORKS64_EXE] recognize_path extract_path
```

## 説明
`extract` サブコマンドは、`recognize` サブコマンドから出力された各文字列を、Stormworks バイナリから取り出した類似の文字列で置き換えます。これにより、OCR の不正確さを補うことができます。

以下の画像は、`extract` サブコマンドで処理する前後のテキストデータを比較したものです。左が処理前、右が処理後です。処理前のテキストデータでは "1" を "l" と間違えるなどの誤認識が散見されるのに対して、処理後のテキストデータではそれらの誤認識が適切に修正されています。

![](https://i.imgur.com/dqRFsTD.png)

`extract` サブコマンドを実行するには、まず下記の準備作業が必要です。
- インストールがまだの場合は、[README.md](README.md#インストール) に従いインストールを済ませてください。
- 先に `recognize` サブコマンドを実行して、テキストデータを用意してください。
  - `recognize` サブコマンドの使い方は [usage-recognize.md](usage-recognize.md) を参照ください。

準備が出来たら、`extract` サブコマンドを実行します。引数は以下の通りに設定してください。
- 位置引数で、入出力するテキストファイルを指定してください。
  - 入力するテキストファイルは、`recognize` サブコマンドから出力されたものを使用してください。
  - なお、入出力の両方にファイルではなくフォルダを指定すると、入力フォルダ直下のファイルを一括処理して、結果を出力フォルダ直下に格納します。各出力ファイルの名前は、入力ファイルの名前と同じになります。

以下はコマンド例です。
```sh
# 準備
cd src/                     # 本リポジトリの src/ フォルダに移動
.venv\Scripts\activate.bat  # 仮想環境の有効化

# Addon.ocr.txt を処理して、結果を Addon.ext.txt に出力する場合
python -m sw_luadocs extract Addon.ocr.txt Addon.ext.txt

# Input/ フォルダに格納されているファイルを一括処理して、結果を Output/ フォルダに出力する場合
python -m sw_luadocs extract Input/ Output/
```

`extract` サブコマンドによりほとんどの誤記は自動的に修正できますが、完璧ではありません。時折、Stormworks バイナリの中から誤ったテキストデータを選択して出力することがあります。ユーザーは、`extract` サブコマンドから出力されるテキストファイルを目視で確認して、必要に応じて誤記を修正する必要があります。

`extract` サブコマンドでの作業が完了したら、次は `export` サブコマンドでテキストエディタを Markdown などのマークアップ形式に変換します。[usage-export.md](usage-export.md) を参照ください。

`extract` サブコマンドは、システムにインストールされている Stormworks バイナリの場所を自動的に検出します。もし自動検出に失敗した場合は例外が発生します。この場合は、以下の手順で対処してください。
- まだ Stormworks をインストールしていない場合は、[README.md](README.md#インストール) に従ってインストールしてください。
- Stormworks を既にインストールしているにもかかわらず上記の例外が発生する場合は、`--stormworks32-exe` 引数および `--stormworks64-exe` 引数で Stormworks バイナリの場所を指定してください。
  - `--stormworks32-exe` では `stormworks.exe`（32bit 版の Stormworks バイナリ）を指定してください。
  - `--stormworks64-exe` では `stormworks64.exe`（64bit 版の Stormworks バイナリ）を指定してください。
  - `--stormworks32-exe` と `--stormworks64-exe` を両方とも指定してください。片方のみでは動作しません。

## コマンドラインオプション
### 位置引数
- `recognize_path`：`recognize` サブコマンドから出力されたテキストファイルの格納場所
  - ファイルが指定された場合は、そのファイルを処理します。
  - フォルダが指定された場合は、そのフォルダの直下にあるファイルを全て処理します。
  - flatdoc 形式のテキストファイルを入力してください。flatdoc については [usage-export.md](usage-export.md#flatdoc) の flatdoc 章を参照ください。
- `extract_path`：テキストファイルの出力先
  - `recognize_path` でファイルを指定した場合は、この引数もファイルを指定してください。
  - `recognize_path` でフォルダを指定した場合は、この引数もフォルダを指定してください。このフォルダの直下にファイルを出力します。各出力ファイルの名前は、対応する入力ファイルの名前と同じになります。
  - flatdoc 形式のテキストファイルが出力されます。flatdoc については [usage-export.md](usage-export.md#flatdoc) の flatdoc 章を参照ください。

### オプション
- `-h`：ヘルプメッセージを出力して終了
- `--stormworks32-exe`：32bit 版 Stormworks バイナリの場所
  - 未指定の場合は自動検出します。
  - 32bit 版と 64bit 版両方の Stormworks バイナリが必要です。片方のみでは動作しません。
- `--stormworks64-exe`：64bit 版 Stormworks バイナリの場所
  - 未指定の場合は自動検出します。
  - 32bit 版と 64bit 版両方の Stormworks バイナリが必要です。片方のみでは動作しません。
