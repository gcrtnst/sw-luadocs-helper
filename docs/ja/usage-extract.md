# `extract` サブコマンド
このページでは `extract` サブコマンドの使い方を説明します。

## 概要
```
python -m sw_luadocs extract [-h] [--stormworks32-exe STORMWORKS32_EXE] [--stormworks64-exe STORMWORKS64_EXE] recognize_path extract_path
```

## 説明
`extract` サブコマンドは、`recognize` サブコマンドから出力された各文字列を、Stormworks バイナリから取り出した類似の文字列で置き換えます。これにより、OCR の不正確さを補うことができます。

以下の画像は、`extract` サブコマンドで処理する前後のテキストデータを比較したものです。左が処理前、右が処理後です。処理前のテキストデータでは "1" を "l" と間違えるなどの誤認識が散見されるのに対して、処理後のテキストデータではそれらの誤認識が適切に修正されています。

![extract サブコマンドでの処理前後の比較](https://i.imgur.com/dqRFsTD.png)

`extract` サブコマンドを実行するには、まず下記の準備作業が必要です。
- インストールがまだの場合は、[README.md](README.md) に従いインストールを済ませてください。
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
.venv/Scripts/activate.bat  # 仮想環境の有効化

# Addon.ocr.txt を処理して、結果を Addon.ext.txt に出力する場合
python -m sw_luadocs extract Addon.ocr.txt Addon.ext.txt

# Input/ 直下に格納されているファイルを一括処理して、結果を Output/ 直下に出力する場合
python -m sw_luadocs extract Input/ Output/
```

`extract` サブコマンドによりほとんどの誤記は修正できますが、完璧ではありません。時折、Stormworks バイナリの中から誤ったテキストデータを選択して出力することがあります。ユーザーは、`extract` サブコマンドから出力されるテキストファイルを目視で確認して、必要に応じて誤記を修正する必要があります。

`extract` サブコマンドは、システムにインストールされている Stormworks バイナリの場所を自動的に検出します。もし自動検出に失敗した場合は例外が発生します。この場合は、以下の手順で対処してください。
- まだ Stormworks をインストールしていない場合は、[README.md](README.md) に従ってインストールしてください。
- Stormworks を既にインストールしているにもかかわらず上記の例外が発生する場合は、`--stormworks32-exe` 引数および `--stormworks64-exe` 引数で Stormworks バイナリの場所を指定してください。
  - `--stormworks32-exe` では `stormworks.exe`（32bit 版の Stormworks バイナリ）を指定してください。
  - `--stormworks64-exe` では `stormworks64.exe`（64bit 版の Stormworks バイナリ）を指定してください。
  - `--stormworks32-exe` と `--stormworks64-exe` を両方とも指定してください。片方のみでは動作しません。
