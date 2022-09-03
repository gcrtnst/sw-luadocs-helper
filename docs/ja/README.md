# sw-luadocs-helper
sw-luadocs-helper は、Stormworks の Lua ヘルプを読み取って Markdown 化するコンソールアプリケーションです。

## 説明
sw-luadocs-helper は、OCR やバイナリからのデータ抽出などの手段を使って、Stormworks 内の Lua ヘルプを読み取ります。読み取った Lua ヘルプは Markdown 等の一般的なマークアップ形式で記述されたテキストファイルとして出力されるため、ユーザーはテキストエディタやブラウザ等の使い慣れたアプリケーションを使用して、それらを快適に閲覧することができます。

![](https://i.imgur.com/GiOi9kp.png)

なお、sw-luadocs-helper は 100% 正確に Lua ヘルプを読み取れるわけではありません。Stormworks の全 Lua ヘルプに対して sw-luadocs-helper を実行すると、数件の誤りが発生します。そのため、ユーザーは出力された Lua ヘルプを目視で確認して、誤りを修正しないといけません。とはいえ、手動で書き写すよりは圧倒的に楽でしょう。

## 背景
[Stormworks: Build and Rescue](https://store.steampowered.com/app/573090/Stormworks_Build_and_Rescue/) はサンドボックス型シミュレーションゲームです。このゲームでは、プレイヤーはビークルやアドオンを設計して、それをサンドボックス環境内で動作させることができます。これらのビークルやアドオンは Lua を使用してプログラミングすることができます。

Stormworks で実行される Lua では、いくつかの標準ライブラリに加えて、ビークルやアドオンを制御するための API を使うことができます。これらの API についてはゲーム内で閲覧できる Lua ヘルプで説明されています。しかし、この Lua ヘルプには以下のような問題点があります。
- ゲーム内でしか閲覧できません。
  - 閲覧するにはいちいちゲームを起動する必要があります。
  - 出先など、ゲームをプレイできない環境では閲覧できません。
- 検索機能がありません。
  - プレイヤーは目的の記述を目視で探し当てる必要があります。
- 翻訳機能がありません。
  - プレイヤーは英語に習熟している必要があります。

そこで、この Lua ヘルプを Markdown ファイルに書き写すことにしました。これにより、Lua ヘルプをゲーム外で閲覧でき、検索も可能で、機械翻訳も簡単にできるようになります。ただ、Stormworks は 2 週間に 1 回の頻度で更新されており、その度に手動で Lua ヘルプを書き写すのは億劫でした。そこで、自動的に Lua ヘルプを書き写すことができるアプリケーションの開発に至りました。

## 動作環境
sw-luadocs-helper を使用するには下記の環境が必要です。
- Windows
  - Win32 API を使用するため、Mac や Linux では動作しません。
- 1920x1080 解像度に対応しているモニタ
  - OCR に必要です。

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
- [tessdata_best](https://github.com/tesseract-ocr/tessdata_best) / [eng.traineddata](https://github.com/tesseract-ocr/tessdata_best/blob/main/eng.traineddata)
  - Tesseract の tessdata フォルダに格納してください。

次に、適当な場所でコマンドプロンプトを開いて、以下の手順で sw-luadocs-helper をセットアップしてください。

```sh
git clone "https://github.com/gcrtnst/sw-luadocs-helper.git"  # 本リポジトリをローカルにクローン
cd sw-luadocs-helper/src                                      # 本リポジトリの src/ フォルダに移動
python -m venv .venv --upgrade-deps                           # 仮想環境を作成
.venv\Scripts\activate.bat                                    # 仮想環境の有効化
pip install -r requirements.txt                               # 依存パッケージのインストール
```

これでインストールは完了です。

以降、sw-luadocs-helper を使用する際は、本リポジトリの `src/` フォルダをカレントディレクトリにして、仮想環境を有効化（`.venv\Scripts\activate.bat`）してから、コマンドを実行してください。

## 使い方
sw-luadocs-helper は複数のサブコマンドで構成されています。sw-luadocs-helper を使用して Lua ヘルプを書き写すには、以下の手順に従います。各手順の実施方法は、それぞれのサブコマンドのドキュメントを参照ください。
1. `capture` サブコマンドを使用して、ゲーム画面上に表示されている Lua ヘルプを撮影
    - `capture` サブコマンドのドキュメント：[usage-capture.md](usage-capture.md)
2. `recognize` サブコマンドを使用して、撮影したスクリーンショットに対して文字認識を実施
    - `recognize` サブコマンドのドキュメント：[usage-recognize.md](usage-recognize.md)
3. `extract` サブコマンドを使用して、認識した文字列をもとに Stormworks バイナリから文字列を取得
    - `extract` サブコマンドのドキュメント：[usage-extract.md](usage-extract.md)
4. `export` サブコマンドを使用して、取得したテキストデータを Markdown などのマークアップ形式に変換
    - `export` サブコマンドのドキュメント：[usage-export.md](usage-export.md)

## 開発
sw-luadocs-helper の開発時は以下のアプリケーションを使用します。いずれも最新のバージョンを選択してください。
- [Black](https://github.com/psf/black)
  - sw-luadocs-helper の Python コードはすべて Black を使用して整形します。
  - 設定はすべてデフォルトです。
  - `pip install black`
- [Flake8](https://github.com/pycqa/flake8)
  - sw-luadocs-helper の Python コードすべてに対して警告が発生しないようにします。
  - 設定ファイルは本リポジトリの `src/.flake8` にあります。
  - `pip install flake8`

## ライセンス
sw-luadocs-helper のライセンスについては、本リポジトリのルートフォルダに格納されている [LICENSE](../../LICENSE) ファイルを参照ください。
