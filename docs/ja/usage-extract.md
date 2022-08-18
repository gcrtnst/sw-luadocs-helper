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
