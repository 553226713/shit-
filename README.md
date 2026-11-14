# shit加密

Linux 桌面文件加解密客户端，当前版本 **1.0.11**。

配置监控目录后，通过 FUSE 在原路径提供文件视图。监控目录内不按目录名、文件名或扩展名排除；已有明文和密文保持原有格式。新建文件可选明文或加密，默认明文。解密仍受程序权限和服务器策略约束。重命名保留源文件状态，临时文件替换不会继承目标格式；版本控制程序也按普通授权规则访问，受信程序可能提交明文。

## 使用

安装构建出的 amd64 安装包：

```bash
sudo apt install ./shit-encryption_1.0.11_amd64.deb
```

从应用列表打开“shit加密”，配置服务器、同步策略并添加监控目录。首次启动监控完成一次管理员授权，之后启动、重新登录和休眠恢复无需重复输入系统密码。详细说明见 [安装说明](packaging/安装说明.txt) 和 [使用文档](USAGE.txt)。

## 源码运行与构建

需要 x86_64 Linux、Python 3、GTK 4.10/PyGObject、systemd 用户会话和 `/dev/fuse`。源码构建引擎另需 C++20 编译器及 libfuse 3.18 以上的开发文件和运行库。安装包携带所需 FUSE 动态库，源码构建仍需准备开发环境。

```bash
python3 engine2/build.py
./start.sh
```

原生服务器登录客户端需另行提供，仓库不包含完整的原厂客户端。将其运行目录设置为 `YT_NATIVE_CLIENT_ROOT`，目录中需包含经过版本校验的 `files/bin/svchost` 和 `files/bin/dotimer.sh`。程序也会查找 `vendor/native-client` 及已安装的原厂客户端目录。构建安装包使用相同的查找规则：

```bash
export YT_NATIVE_CLIENT_ROOT=/absolute/path/to/native-client
python3 packaging/build_deb.py
```

安装包、安装说明和校验文件默认输出至当前项目目录下的 `dist/`。其他构建工具和依赖见 [构建脚本](packaging/build_deb.py)。

## 验证

```bash
python3 -m unittest discover -s tests
python3 engine2/verify_editor_saves.py
python3 engine2/verify_permissions.py
python3 engine2/verify_new_file_mode.py
```

实际挂载验证需要可用的 `sudo` 与 FUSE；Java 保存验证需要 JDK。`verify_new_file_mode.py` 还依赖另行准备的开发归档 `../linux-client-archive/probe_cipher.py` 作为原 Windows 算法校验工具。上述归档不在仓库中；常规单元测试和 Java 保存验证不依赖它。

## 配置与源码归档

本机配置、策略密钥和 `state/` 运行数据不纳入 Git。安装版使用 `~/.config/shit-encryption/` 和 `~/.local/state/shit-encryption/`，源码版使用仓库内的 `config/` 和 `state/`。

```bash
sh packaging/archive-source.sh
```

此命令仅导出 Git HEAD 中已提交的源码，不包含本机配置、未提交修改或安装包。
