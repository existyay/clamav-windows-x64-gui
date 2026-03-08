# 嵌入 ClamAV 二进制文件

将 ClamAV Windows 二进制文件放入此目录，构建时会自动嵌入到 exe 中。

## 使用方法

1. 从 [ClamAV 官方](https://www.clamav.net/downloads) 下载 Windows 版本
2. 将以下文件复制到此目录：
   - `clamscan.exe`
   - `freshclam.exe`
   - 所有相关 `.dll` 文件
3. 重新构建：`cargo build --release`

构建后的 `clamav-gui.exe` 将包含所有二进制文件，首次运行时自动释放。

## 不嵌入的情况

如果此目录为空（不含任何 exe/dll），构建的 GUI 将正常工作，
但需要用户手动将 ClamAV 二进制文件放到程序目录下的 `clamav/` 文件夹中。
