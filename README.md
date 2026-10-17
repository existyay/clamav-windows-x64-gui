# ClamAV Windows x64 GUI

<p align="center">
  <a href="https://github.com/existyay/clamav-windows-x64-gui/actions"><img src="https://github.com/existyay/clamav-windows-x64-gui/actions/workflows/build-gui.yml/badge.svg" alt="Build"></a>
  <a href="https://github.com/existyay/clamav-windows-x64-gui/releases/latest"><img src="https://img.shields.io/github/v/release/existyay/clamav-windows-x64-gui?label=download" alt="Release"></a>
  <img src="https://img.shields.io/badge/platform-Windows%20x64-blue" alt="Platform">
  <img src="https://img.shields.io/badge/license-GPL--2.0-green" alt="License">
</p>

基于 ClamAV 引擎的 Windows 现代图形界面杀毒软件。从源码编译，开箱即用的便携版。

## 功能特性

- **📊 总览** — 引擎状态、威胁数量、实时保护状态、病毒库版本一览
- **🔍 病毒扫描** — 快速/全盘/自定义目标（支持拖放），可选递归、压缩包、邮件、PDF、OLE2、HTML 与启发式告警
- **🛡 实时保护** — 基于 Windows ETW 的文件与进程行为监控（YAMAGoya + Sigma/YAML/YARA 规则）
- **🔄 病毒库更新** — 一键调用 freshclam 在线更新，可取消并实时显示下载进度
- **🔒 隔离区** — 威胁文件隔离管理，支持筛选、单项恢复与删除
- **⚙ 设置** — 扫描预设（快速/均衡/彻底）、正则排除规则、并发进程数与文件大小限制
- **📋 日志** — 扫描 / 实时保护 / 更新三类日志，支持导出与复制

### 界面风格

采用「类纸风格」：暖白纸面与深色墨板两套配色、纸张纹理底纹、单色矢量图标，
所有控件自绘以保持统一的印刷质感。界面跟随系统 DPI（PerMonitorV2），
中文使用系统自带字体渲染。

## 下载安装

从 [Releases](https://github.com/existyay/clamav-windows-x64-gui/releases/latest) 下载最新版 `ClamAV-GUI-Portable-x64.zip`。

> **只有一个发布。** 每次推送都会自动构建并发布，新产物直接覆盖 `latest`：下载链接
> 永远指向最近一次构建，历史版本不再保留。这次构建对应的版本、提交号与构建号写在
> 包内的 `BUILD_INFO.txt` 里。

解压后直接运行 `ClamAV-Scanner.exe`，无需安装。首次使用请先更新病毒库。

### 目录结构

```
ClamAV-GUI-Portable/
├── ClamAV-Scanner.exe      # GUI 主程序
├── fonts/                   # 可选：随包分发的中文字体（.otf/.ttf/.ttc）
├── clamav/
│   ├── clamscan.exe         # 扫描引擎
│   ├── freshclam.exe        # 病毒库更新
│   ├── clamd.exe            # 守护进程
│   ├── clamdscan.exe        # 守护进程客户端
│   ├── *.dll                # 依赖库
│   ├── certs/               # CA 证书
│   ├── database/            # 病毒库
│   ├── freshclam.conf       # 更新配置
│   └── clamd.conf           # 守护进程配置
├── quarantine/              # 隔离区
├── logs/                    # 日志
└── yamagoya/                # 实时保护引擎与规则
```

### 权限说明

程序以**当前用户权限**启动（`asInvoker`），不会在每次打开时弹出 UAC 提示——这样便携版在
任何目录下都能直接双击运行。

代价是：`C:\Windows` 下的部分受保护位置**无法读取，也无法把检出的文件移入隔离区**。
需要处理这些位置时，请在 *设置 → 外观与启动* 中点击 **“以管理员身份重启”**，程序会通过
系统的 `runas` 动词重新启动自己并请求提权。

> 早期版本在清单里写死了 `requireAdministrator`，但同时又与工具链自带的清单冲突，
> 结果是 GNU 构建根本不提权、而测试构建又要求提权导致 `cargo test` 无法运行。
> 现在统一为按需提权。

## 技术栈

| 组件 | 技术 |
|------|------|
| GUI | Rust + [egui](https://github.com/emilk/egui) 0.31 (GPU 加速即时模式渲染) |
| 杀毒引擎 | [ClamAV](https://github.com/Cisco-Talos/clamav) 1.6.0 (C/Rust, 从源码编译) |
| 编译器 | MSVC 14.x (Visual Studio 2022)，亦支持 `x86_64-pc-windows-gnu` |
| C 依赖 | OpenSSL, libcurl, libxml2, pcre2, zlib, bzip2, json-c (via vcpkg) |
| CI/CD | GitHub Actions — 自动构建 + 发布 |

## 从源码构建

### 环境要求

- Windows 10/11 x64
- Visual Studio 2022 (MSVC C/C++ 工具集)
- CMake 3.20+
- Rust 1.70+
- vcpkg

### 构建步骤

```powershell
# 1. 克隆仓库
git clone https://github.com/existyay/clamav-windows-x64-gui.git
cd clamav-windows-x64-gui

# 2. 安装 C 库依赖
vcpkg install --triplet x64-windows

# 3. 编译 ClamAV 引擎
mkdir build; cd build
cmake .. -A x64 `
  -D CMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
  -D CMAKE_INSTALL_PREFIX="install" `
  -D ENABLE_TESTS=OFF -D ENABLE_MILTER=OFF -D ENABLE_EXAMPLES=OFF
cmake --build . --config Release
cmake --build . --config Release --target install
cd ..

# 4. 编译 GUI
$base = "$PWD\vcpkg_installed\x64-windows"
$env:OPENSSL_DIR = $base
$env:OPENSSL_LIB_DIR = "$base\lib"
$env:OPENSSL_INCLUDE_DIR = "$base\include"
cd gui
cargo build --release
```

运行单元测试（覆盖命令行参数组装、`clamscan` 输出解析、配置迁移与路径/体积格式化）：

```powershell
cd gui
cargo test
```

> **关于中文字体**
>
> 界面本身会直接使用 Windows 自带的中文字体（Microsoft YaHei 等），因此无需手动准备字体。
> 如果目标机器缺少中文字体，可以把任意 `.otf` / `.ttf` / `.ttc` 字体放到可执行文件同级的
> `fonts\` 目录，程序会优先使用它：
>
> ```
> dist\ClamAV-GUI-Portable\
>   ClamAV-Scanner.exe
>   fonts\
>     NotoSansSC-Regular.otf
> ```
>
> 请**不要**把 `C:\Windows\Fonts` 下的字体（`msyh.ttc`、`simsun.ttc` 等）打包进发布包——
> 它们是微软的专有字体，不允许再分发。需要随包分发时请使用 SIL Open Font License 的
> [Noto Sans SC](https://github.com/notofonts/noto-cjk)。

## 许可证

ClamAV 引擎基于 [GPL-2.0](COPYING.txt) 许可证。
["Packages"](https://docs.clamav.net/manual/Installing/Packages.html).

### Using an Installer

The following install packages are available for download from
[clamav.net/downloads](https://www.clamav.net/downloads):

- Linux - Debian and RPM packages for x86_64 and i686. *New in v0.104.*
- macOS - PKG installer for x86_64 and arm64 (universal). *New in v0.104.*
- Windows - MSI installers and portable ZIP packages for win32 and x64.

To learn how to use these packages, refer to the online manual under
["Installing"](https://docs.clamav.net/manual/Installing.html#installing-with-an-installer).

### Build from Source

For step-by-step instructions, refer to the online manual:
- [Unix/Linux/Mac](https://docs.clamav.net/manual/Installing/Installing-from-source-Unix.html)
- [Windows](https://docs.clamav.net/manual/Installing/Installing-from-source-Windows.html)

The source archive for each release includes a copy of the documentation for
[offline](docs/html/UserManual.html) reading.

A reference with all of the available build options can be found in the
[INSTALL.md](INSTALL.md) file.

You can find additional advice for developers in the online manual under
["For Developers"](https://docs.clamav.net/manual/Development.html).

### Upgrading from a previous version

Visit [the FAQ](https://docs.clamav.net/faq/faq-upgrade.html) for tips on how
to upgrade from a previous version.

## Join the ClamAV Community

The best way to get in touch with the ClamAV community is to join our
[mailing lists](https://docs.clamav.net/faq/faq-ml.html).

You can also join the community on our
[ClamAV Discord chat server](https://discord.gg/6vNAqWnVgw).

## Want to make a contribution?

The ClamAV development team welcomes
[code contributions](https://github.com/Cisco-Talos/clamav),
improvements to
[our documentation](https://github.com/Cisco-Talos/clamav-documentation),
and also [bug reports](https://github.com/Cisco-Talos/clamav/issues).

Thanks for joining us!

## Licensing

ClamAV is licensed for public/open source use under the GNU General Public
License, Version 2 (GPLv2).

See `COPYING.txt` for a copy of the license.

### 3rd Party Code

ClamAV contains a number of components that include code copied in part or in
whole from 3rd party projects and whose code is not owned by Cisco and which
are licensed differently than ClamAV. These include:

- Yara: Apache 2.0 license
  - Yara has since switched to the BSD 3-Clause License;
    Our source is out-of-date and needs to be updated.
- 7z / lzma: public domain
- libclamav's NSIS/NulSoft parser includes:
  - zlib: permissive free software license
  - bzip2 / libbzip2: BSD-like license
- OpenBSD's libc/regex: BSD license
- file: BSD license
- str.c: Contains BSD licensed modified-implementations of strtol(), stroul()
  functions, Copyright (c) 1990 The Regents of the University of California.
- pngcheck (png.c): MIT/X11-style license
- getopt.c: MIT license
- Curl: license inspired by MIT/X, but not identical
- libmspack: LGPL license
- UnRAR (libclamunrar): a non-free/restricted open source license
  - Note: The UnRAR license is incompatible with GPLv2 because it contains a
    clause that prohibits reverse engineering a RAR compression algorithm from
    the UnRAR decompression code.
    For this reason, libclamunrar/libclamunrar_iface is not linked at all with
    libclamav. It is instead loaded at run-time. If it fails to load, ClamAV
    will continue running without RAR support.

See the `COPYING` directory for a copy of the 3rd party project licenses.

## Acknowledgements

Credit for contributions to each release can be found in the [News](NEWS.md).

ClamAV is brought to you by
[the ClamAV Team](https://www.clamav.net/about.html#credits)
