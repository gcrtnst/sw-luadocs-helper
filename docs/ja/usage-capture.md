# `capture` サブコマンド
このページでは、`capture` サブコマンドの使い方を説明します。

## 概要
```
python -m sw_luadocs capture [-h] -c CONFIG capture_file
```

## 説明
`capture` サブコマンドは、Stormworks のゲーム画面上に表示されている Lua ヘルプのスクリーンショットを撮影します。このサブコマンドは、Lua ヘルプをスクロールすることで、表示されている範囲のみではなく Lua ヘルプ全体を撮影します。

以下は撮影されたスクリーンショットの例です。

![capture サブコマンドによって撮影されたスクリーンショットの例](https://i.imgur.com/fOfsdKn.png)

`capture` サブコマンドを使用するには、まず下記の準備作業が必要です。
- インストールがまだの場合は、[README.md](README.md) に従いインストールを済ませてください。
- Stormworks の設定で、ウィンドウモードをフルスクリーンに、解像度を 1920x1080 に設定してください。
- 予め Stormworks を起動して、撮影したい Lua ヘルプを表示させておいてください。

準備が出来たら、`capture` サブコマンドを実行します。引数は以下の通りに設定してください。
- `-c CONFIG` オプションで設定ファイルを指定してください。
  - 設定ファイルは本リポジトリの `cfg/` フォルダにあります。
  - Addon Lua のヘルプを撮影する場合は `sw_luadocs_addon.toml` を、Vehicle Lua のヘルプを撮影する場合は `sw_luadocs_vehicle.toml` を指定してください。
- 位置引数で、撮影したスクリーンショットの出力先ファイルを指定してください。

以下はコマンド例です。
```sh
# 準備
cd src/                     # 本リポジトリの src/ フォルダに移動
.venv/Scripts/activate.bat  # 仮想環境の有効化

# Addon Lua ヘルプを撮影して、結果を Addon.png に出力する場合
python -m sw_luadocs capture -c ../cfg/sw_luadocs_addon.toml Addon.png

# Vehicle Lua ヘルプを撮影して、結果を Vehicle.png に出力する場合
python -m sw_luadocs capture -c ../cfg/sw_luadocs_vehicle.toml Vehicle.png
```

`capture` サブコマンドは以下の順で動作します。
1. Stormworks のウィンドウをアクティブ化します。
2. Lua ヘルプの一番上までスクロールします。
3. 画面を撮影します。
4. 少し下にスクロールします。
5. Lua ヘルプの一番下に到達するまで 3, 4 を繰り返します。
6. Stormworks のウィンドウを最小化します。
7. 撮影したスクリーンショットを全て連結して、ファイルに出力します。

`capture` サブコマンドの実行中はマウスやキーボードに触れないでください。実行中に操作すると、スクリーンショットの撮影に失敗する恐れがあります。

## コマンドラインオプション
### 位置引数
- `capture_file`：撮影したスクリーンショットの出力先ファイル
  - Pillow を使用して画像を書き出します。サポートされている画像フォーマットの一覧は `python -m PIL` を参照ください。

### オプション
- `-h`：ヘルプメッセージを出力して終了
- `-c CONFIG`, `--config CONFIG`：TOML 形式の設定ファイル（必須）
  - 本リポジトリの `cfg/` フォルダに格納されているファイルを指定してください。`sw_luadocs_addon.toml` は Addon Lua のヘルプ用、`sw_luadocs_vehicle.toml` は Vehicle Lua のヘルプ用です。
  - 使用する設定項目の一覧は[設定ファイル](#設定ファイル)の章を参照ください。

## 設定ファイル
`capture` サブコマンドは以下の設定項目を使用します。

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

- `screen_width`, `screen_height`：画面解像度
  - Stormworks の画面解像度がこの設定項目と一致しない場合は例外を発生させます。
  - この設定項目を変更する場合は、座標に関連する他の設定項目の修正も検討してください。
- `scroll_x`, `scroll_y`：スクロール時のマウスカーソル位置
  - Lua ヘルプをスクロールする際、マウスカーソルをこの位置まで移動させた上で、マウスホイールの回転をシミュレートします。
- `scroll_init_delta`：Lua ヘルプの一番上までスクロールする際の、マウスホイールの回転量
  - 正数を指定してください。
  - マウスホイールのノッチ1つ分の回転量は120です。
- `scroll_down_delta`：Lua ヘルプを1回だけ下にスクロールする際の、マウスホイールの回転量
  - 負数を指定してください。
  - マウスホイールのノッチ1つ分の回転量は120です。
- `scroll_threshold`：スクロールが一番下まで到達したかどうか判断するための閾値
  - マウスホイールを回転させた後、実際にスクロールしたピクセル数がこの数値以下であれば、スクロールが一番下まで到達したと判断します。
- `capture_area_x`, `capture_area_y`, `capture_area_w`, `capture_area_h`：画面の撮影領域
  - Lua ヘルプが表示されている領域を指定してください。
  - それぞれ、X 座標、Y 座標、幅、高さです。
- `capture_template_ratio`：テンプレートマッチングに使用する領域の割合
  - スクロールしたピクセル数を計算するために、スクロール前の画像からこの割合だけ画像を切り出して、スクロール後の画像とのテンプレートマッチングを行います。
- `activate_delay`：Stormworks のウィンドウをアクティブ化してから、ゲーム画面が表示されるまでの待機時間
- `scroll_mouse_delay`：マウスカーソルを移動させてから、Stormworks にそれが認識されるまでの待機時間
- `scroll_smooth_delay`：マウスホイールを回転させてから、スクロールアニメーションが終了するまでの待機時間
