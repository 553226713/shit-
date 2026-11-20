# shit加密

Linux 桌面文件加解密客户端，当前版本 **1.0.15**。

配置监控目录后，通过 FUSE 在原路径提供文件视图。新建文件可选明文或加密，默认明文。在“监控目录 → 排除目录”中可以选择具体子目录，例如项目的 `node_modules`。排除规则先于文件类型匹配，命中后整个子树直接按原始字节访问。已有密文以密文呈现。监控范围内的解密受程序权限和服务器策略约束。普通移动保留源文件状态，受信程序在监控范围内用明文临时文件覆盖已有密文目标时保持目标加密。系统 Git 使用原始文件字节，密文暂存、提交、推送和检出均保持密文；差异和历史通过只读显示转换查看。

“监控目录 → 监控文件类型”预填常用源码、脚本和前端文件扩展名，例如 `.java, .py, .ts`。只监控列表中的类型，清空后所有文件直接按原始字节访问。“排除目录”默认按目录名排除 `node_modules`、`build`、`target`、`dist`、`tmp` 和常见缓存等目录，可在界面查看清单或关闭默认规则。新建文件只有在目录未排除、扩展名匹配、全局新建格式设为加密且程序符合策略时才会加密。常规移动或更名保留文件原有字节，后续访问按新路径判断。从排除目录移来的文件不能直接覆盖已有受监控密文。

Git 提交严格跟随文件落盘状态：明文提交为明文，密文提交为密文，不在提交时额外加密或解密。概览中的“新建文件格式”切换即保存；只有监控报告实际采用该设置时才显示“已生效”。它不批量转换已有文件，停止监控或未运行客户端时不会自动加密。

## 使用

安装构建出的 amd64 安装包：

```bash
sudo apt install ./shit-encryption_1.0.15_amd64.deb
```

从应用列表打开“shit加密”，配置服务器、同步策略并添加监控目录。首次启动监控完成一次管理员授权，之后启动、重新登录和休眠恢复无需重复输入系统密码。详细说明见 [安装说明](packaging/安装说明.txt) 和 [使用文档](USAGE.txt)。

界面分为“概览、监控目录、程序权限、服务器与策略”四页。目录变更和新建格式即时保存；程序权限与服务器配置分别点击本页“应用”，不会顺带保存其他页面的草稿。目录显示真实挂载与异常原因，连接检测、策略同步和监控运行状态独立反馈；关闭窗口隐藏到托盘并保留未应用草稿。

1.0.15 拒绝将已有密文作为明文写入受监控的加密文件，避免生成双层密文。复制遇到拒绝时，目标可能保留空文件或已经写入的片段。

1.0.13 修复受信 Git 提交解密视图，以及明文临时文件覆盖密文目标造成格式降级的问题。Git 传输身份按受保护的系统可执行文件核验，不能仅靠文件名或脚本参数获得。已提交的明文历史不会自动修复，需要另行评估清理；本版本不改写真实仓库历史。

同版本修复 X11 桌面托盘唤出窗口时缺少有效激活时间戳的问题；被其他应用遮挡或最小化后，唤出会请求正常置前，不设置永久置顶。Wayland 继续使用桌面提供的激活令牌，窗口最终激活由合成器决定。

1.0.12 修复旧授权目录权限不符合要求时，重启重复创建授权记录导致服务立即退出的问题。管理员授权启动时会修复 root 所有的授权目录和普通记录权限，保留已有记录；符号链接、硬链接、特殊文件及非 root 所有的记录仍拒绝使用。界面会显示服务退出原因及日志查询命令，不再仅显示“未运行”。

## 源码运行与构建

需要 x86_64 Linux、Python 3、GTK 4.10/PyGObject、systemd 用户会话和 `/dev/fuse`。源码构建引擎另需 C++20 编译器及 libfuse 3.18 以上的开发文件和运行库。安装包携带所需 FUSE 动态库，源码构建仍需准备开发环境。

```bash
python3 src/engine2/build.py
./start.sh
```

原生服务器登录客户端需另行提供，仓库不包含完整的原厂客户端。将其运行目录设置为 `YT_NATIVE_CLIENT_ROOT`，目录中需包含经过版本校验的 `files/bin/svchost` 和 `files/bin/dotimer.sh`。程序也会查找 `vendor/native-client` 及已安装的原厂客户端目录。构建安装包使用相同的查找规则：

```bash
export YT_NATIVE_CLIENT_ROOT=/absolute/path/to/native-client
python3 packaging/build_deb.py
```

安装包、安装说明和校验文件默认输出至当前项目目录下的 `dist/`。其他构建工具和依赖见 [构建脚本](packaging/build_deb.py)。

源码按职责组织：

```text
src/
  yt_client/          Python 客户端、配置与策略处理
    ui/               GTK 页面和系统托盘
    monitoring/       挂载、授权、隔离视图与用户服务
    cli/              策略管理、命令行隔离启动和 Git 显示入口
    compat/           Git 只读显示转换
  engine2/            C++ 文件引擎、流式转换器及构建工具
  native/             原生策略查询桥接代码
tests/                客户端单元测试及集成验证
  engine2/            引擎验证、性能工具和 C/Java 探针
packaging/            安装包构建、桌面入口、授权规则和安装验证
assets/               图标资源
vendor/               经校验的算法组件
```

根目录只保留项目说明、版本/许可、启动脚本及资源目录。源码命令行工具使用包入口，例如：

```bash
PYTHONPATH=src python3 -m yt_client.cli.policy_manager status
PYTHONPATH=src python3 -m yt_client.cli.yt_run cat /absolute/path/Example.java
```

`start.sh` 会自动设置源码导入路径，无需安装 Python 包。`config/`、`state/` 和 `dist/` 分别是本机配置、运行/构建数据和分发产物，不与源码混放；整理源码不会清空这些目录。

旧根目录下的 Python 文件入口已迁移，不保留兼容副本；前台启动统一使用 `./start.sh --foreground`，原重复包装脚本 `run-yt-control` 已删除。监控服务、授权入口、Git 显示命令和安装包均使用新的源码路径。

## 验证

```bash
python3 -m unittest discover -s tests
python3 tests/engine2/verify_editor_saves.py
python3 tests/engine2/verify_permissions.py
python3 tests/engine2/verify_new_file_mode.py
python3 tests/verify_git_roundtrip.py
```

实际挂载验证需要可用的 `sudo` 与 FUSE；Java 保存验证需要 JDK。Git 验证默认使用合成密文和临时本地裸仓库，也可只读指定历史密文样本，不会向真实远端推送；上述验证不依赖外部开发归档。

## 配置与源码归档

本机配置、策略密钥和 `state/` 运行数据不纳入 Git。安装版使用 `~/.config/shit-encryption/` 和 `~/.local/state/shit-encryption/`，源码版使用仓库内的 `config/` 和 `state/`。

```bash
sh packaging/archive-source.sh
```

此命令仅导出 Git HEAD 中已提交的源码，不包含本机配置、未提交修改或安装包。
