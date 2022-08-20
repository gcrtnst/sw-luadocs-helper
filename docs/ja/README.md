# sw-luadocs-helper
sw-luadocs-helper は、Stormworks 内の Lua ヘルプをゲーム外に複写する手助けをします。

## 背景
[Stormworks: Build and Rescue](https://store.steampowered.com/app/573090/Stormworks_Build_and_Rescue/) はサンドボックス型シミュレーションゲームです。このゲームでは、プレイヤーはビークルやアドオンを設計して、それをサンドボックス環境内で動作させることができます。これらのビークルやアドオンは Lua を使用してプログラミングすることができます。

Stormworks で実行される Lua では、いくつかの Lua 標準ライブラリに加えて、ビークルやアドオンを制御するための独自ライブラリを使うことができます。これらの独自ライブラリについてはゲーム内で閲覧できる Lua ヘルプで説明されています。しかし、この Lua ヘルプには以下のような問題点があります。
- ゲーム内でしか閲覧できません。
  - 閲覧するにはいちいちゲームを起動する必要があります。
  - 出先など、ゲームをプレイできない環境では閲覧できません。
- 検索機能がありません。
  - プレイヤーは目的の記述を目視で探し当てる必要があります。
- 翻訳機能がありません。
  - プレイヤーは英語に習熟している必要があります。

上記のような問題点を解決するために、sw-luadocs-helper を開発しました。

## 機能
sw-luadocs-helper は、OCR やバイナリからのデータ抽出などの手段を使って、Stormworks 内の Lua ヘルプをゲーム外に複写します。複写された Lua ヘルプは Markdown 等の一般的なマークアップ形式で記述されたテキストファイルとなるため、ユーザーはテキストエディタやブラウザ等の一般的なツールを使用して、それらを快適に閲覧することができます。

なお、sw-luadocs-helper は 100% 正確に Lua ヘルプを複写できるわけではありません。Stormworks の全ての Lua ヘルプを複写させると、数件の誤りが発生します。そのため、ユーザーは複写された Lua ヘルプを目視で確認して、誤りを修正しないといけません。とはいえ、手動で複写するよりは圧倒的に楽でしょう。

## 動作環境
sw-luadocs-helper を使用するには下記の環境が必要です。
- Windows
  - Win32 API を使用するため、Mac や Linux では動作しません。

## インストール
まず、sw-luadocs-helper が依存している下記のソフトウェアをインストールしてください。いずれも最新のバージョンを選択してください。
- [Stormworks: Build and Rescue](https://store.steampowered.com/app/573090/Stormworks_Build_and_Rescue/)
- [Python](https://www.python.org/)
  - `winget install Python.Python.3.X`（X はマイナー番号）
- [Git](https://git-scm.com/)
  - `winget install Git.Git`
- [Tesseract](https://github.com/tesseract-ocr/tesseract)
  - UB Mannheim が公開している Windows 向けインストーラは[こちら](https://github.com/UB-Mannheim/tesseract/wiki)。
  - `winget install UB-Mannheim.TesseractOCR`

次に、以下の手順で sw-luadocs-helper をセットアップしてください。

```sh
git clone "https://github.com/gcrtnst/sw-luadocs-helper.git"  # 本リポジトリをローカルにクローン
cd sw-luadocs-helper/src                                      # 本リポジトリの src/ フォルダに移動
python -m venv .venv --upgrade-deps                           # 仮想環境を作成
.venv/Scripts/activate.bat                                    # 仮想環境の有効化
pip install -r requirements.txt                               # 依存パッケージのインストール
```

これでインストールは完了です。

以降、sw-luadocs-helper を使用する際は、本リポジトリの src/ フォルダをカレントディレクトリにして、仮想環境を有効化（`.venv/Scripts/activate.bat`）してから、コマンドを実行してください。

## 使い方
sw-luadocs-helper は複数のサブコマンドで構成されています。sw-luadocs-helper を使用して Lua ヘルプを複写するには、以下の手順に従います。
1. `capture` サブコマンドを使用して、ゲーム画面上に表示されている Lua ヘルプを撮影
2. `recognize` サブコマンドを使用して、撮影したスクリーンショットに対して文字認識を実施
3. `extract` サブコマンドを使用して、認識した文字列をもとに Stormworks バイナリから文字列を取得
4. `export` サブコマンドを使用して、複写したテキストデータを Markdown などのマークアップ形式に変換

それぞれのサブコマンドの使い方は以下のドキュメントを参照ください。
1. [usage-capture.md](usage-capture.md)
2. [usage-recognize.md](usage-recognize.md)
3. [usage-extract.md](usage-extract.md)
4. [usage-export.md](usage-export.md)

## ライセンス
sw-luadocs-helper のライセンスについては、本リポジトリのルートフォルダに格納されている LICENSE ファイルを参照ください。

