# `export` サブコマンド
このページでは `export` サブコマンドの使い方を説明します。

## 概要
```
python -m sw_luadocs export [-h] [-f FORMAT] [--encoding ENCODING] [--newline NEWLINE] load_path save_path
```

## 説明
`export` サブコマンドは、`extract` サブコマンドなどから出力されたテキストファイルを Markdown 等のマークアップ形式に変換します。

`extract` サブコマンドなどから出力されるテキストファイルは sw-luadocs-helper 独自の形式ですが、`export` サブコマンドを使用することでそれを一般的なマークアップ形式に変換できます。これにより、テキストデータを HTML に変換したり、読みやすい形式で表示したりするなど、使い慣れたアプリケーションで加工することができるようになります。

以下の画像は、`export` サブコマンドにより変換される前後のテキストファイルの例です。左が変換前、右が変換後です。

![](https://i.imgur.com/jhQdxd2.png)

`export` サブコマンドを使用するには、まず下記の準備作業が必要です。
- インストールがまだの場合は、[README.md](README.md#インストール) に従いインストールを済ませてください。

準備が出来たら、`export` サブコマンドを実行します。引数は以下の通りに設定してください。
- `-f FORMAT` でマークアップ形式を指定してください。
  - 指定できるマークアップ形式は `markdown` または `wikiwiki` です。
  - `wikiwiki` とは、主に日本で展開されている無料レンタル Wiki サービス [WikiWiki](https://wikiwiki.jp/) で使用されている記法のことです。[PukiWiki](https://pukiwiki.osdn.jp/) の記法と同じですが、[code プラグイン](https://wikiwiki.jp/sample/Manual/A-D#sd91fd21) が存在することを前提としています。
  - デフォルトでは `markdown` となります。
- 位置引数で、入出力するテキストファイルを指定してください。
  - 入力するテキストファイルは、flatdoc 形式のものを使用してください。
    - `recognize` サブコマンドおよび `extract` サブコマンドから出力されるテキストファイルは flatdoc 形式です。
    - flatdoc 形式の詳細は [flatdoc](#flatdoc) の章を参照ください。
  - なお、入出力の両方にファイルではなくフォルダを指定すると、入力フォルダ直下のファイルを一括処理して、結果を出力フォルダ直下に格納します。

以下はコマンド例です。
```sh
# 準備
cd src/                     # 本リポジトリの src/ フォルダに移動
.venv\Scripts\activate.bat  # 仮想環境の有効化

# Addon.txt を Markdown 形式に変換して、結果を Addon.md に出力する場合
python -m sw_luadocs export Addon.txt Addon.md

# Addon.txt を WikiWiki 形式に変換して、結果を WikiWiki.txt に出力する場合
python -m sw_luadocs export -f wikiwiki Addon.txt WikiWiki.txt

# Input/ フォルダにあるファイルを全て Markdown 形式に変換して、結果を Output/ フォルダに出力する場合
python -m sw_luadocs export Input/ Output/

# Input/ フォルダにあるファイルを全て WikiWiki 形式に変換して、結果を Output/ フォルダに出力する場合
python -m sw_luadocs export -f wikiwiki Input/ Output/
```

`export` サブコマンドによる変換処理は簡易的であり、インライン HTML や特殊記号などのエスケープを実施しません。そのため、入力されるテキストデータによっては、意図しないマークアップが出力されることがあります。ユーザーは `export` サブコマンドから出力されるテキストファイルを目視で確認して、必要に応じてマークアップを修正する必要があります。

## コマンドラインオプション
### 位置引数
- `load_path`：入力ファイルの場所
  - ファイルが指定された場合は、そのファイルを処理します。
  - フォルダが指定された場合は、そのフォルダの直下にあるファイルを全て処理します。
  - flatdoc 形式のテキストファイルを入力してください。flatdoc については [flatdoc](#flatdoc) 章を参照ください。
- `save_path`：出力ファイルの場所
  - `load_path` でファイルを指定した場合は、この引数もファイルを指定してください。
  - `load_path` でフォルダを指定した場合は、この引数もフォルダを指定してください。このフォルダの直下にファイルを出力します。各出力ファイルの名前は、入力ファイルの名前を下記の拡張子でリネームしたものとなります。
    - マークアップ形式が `markdown` の場合、拡張子は `.md` となります。
    - マークアップ形式が `wikiwiki` の場合、拡張子は `.txt` となります。
  - flatdoc 形式のテキストファイルが出力されます。flatdoc については [flatdoc](#flatdoc) 章を参照ください。

### オプション
- `-f FORMAT`, `--format FORMAT`：変換先のマークアップ形式
  - 指定できるマークアップ形式は `markdown` または `wikiwiki` です。
  - デフォルトでは `markdown` となります。
- `--encoding ENCODING`：出力ファイルのエンコーディング
  - 指定できるエンコーディングの一覧は [Python のドキュメント](https://docs.python.org/3/library/codecs.html#standard-encodings) を参照ください。
  - デフォルトは `utf-8` です。
- `--newline NEWLINE`：出力ファイルの改行コード
  - 指定できる改行コードは `LF`、`CR`、`CRLF` のいずれかです。
  - デフォルトは `LF` です。

## flatdoc
flatdoc とは sw-luadocs-helper で使用される独自のマークアップ形式です。HTML や Markdown 等の一般的なマークアップ形式とは異なり階層構造を扱えず、フラットな文章しか表現できないことから、flatdoc と名付けられています。Stormworks の Lua ヘルプを表現できる能力を持ちつつ、プログラムから解析しやすいようにシンプルな設計となっています。

以下は flatdoc 形式のテキストデータの例です。
```
head これは見出しです
body これは1つ目の本文です
body これは2つ目の本文の1行目です
.... これは2つ目の本文の2行目です
code これはコード1行目です
.... これはコード2行目です
```

flatdoc 形式のテキストデータは UTF-8 エンコーディングで、改行コードは LF です。

各行は以下の文字列で構成されています。
- 先頭1～4文字目：要素の種類を表す文字列
  - `head`（見出し）、`body`（本文）、`code`（コード）、`....` のいずれか
  - `....` は前の行の要素が継続していることを表します。
- 先頭5文字目：空白文字固定
- 先頭6文字目以降：その要素が持つテキスト

上で例に挙げたテキストデータは、以下の4つの要素を持つ文章を表しています。
- `これは見出しです` というテキストを持つ見出し要素
- `これは1つ目の本文です` というテキストを持つ本文要素
- `これは2つ目の本文の1行目です` と `これは2つ目の本文の2行目です` という2行のテキストを持つ本文要素
- `これはコード1行目です` と `これはコード2行目です` という2行のテキストを持つコード要素

上で例に挙げたテキストデータを `export` サブコマンドで Markdown に変換すると以下のようになります。

``````markdown
# これは見出しです

これは1つ目の本文です

これは2つ目の本文の1行目です
これは2つ目の本文の2行目です

```lua
これはコード1行目です
これはコード2行目です
```
``````
