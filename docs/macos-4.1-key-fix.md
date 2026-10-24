# macOS 微信 4.1.x 密钥提取修复说明

> 适用范围：Apple Silicon Mac，macOS ≥ 26.3.1，微信 Mac 4.1.9 – 4.1.15（已在 4.1.13 与 4.1.15 上实测通过）。
> 本文记录本分支相对上游 `huohuoer/wechat-cli` v0.2.4 的全部改动、修复原理与新机器安装步骤。

## 1. 问题背景

上游 v0.2.4 的 macOS 密钥扫描器（`wechat_cli/bin/find_all_keys_macos.arm64`）只能在微信进程内存中搜索
`x'<key_hex><salt_hex>'` 形式的明文十六进制字面量（SQLCipher 密钥的 PRAGMA 格式）。

微信 4.1.x 改变了密钥的存放方式：

- 数据库密钥不再以明文 `x'...'` 字面量出现在内存中，而是放进 WCDB 的
  `com.Tencent.WCDB.Config.Cipher` 配置对象里；
- 该值是一个 **XOR 混淆的短 blob**，解码后才是 `x'key+salt'` 字面量；
- 校验算法从 HMAC-SHA512 变为 **HMAC-SHA1**（PBKDF2 迭代 64000 次）。

表现为：扫描器能找到全部加密数据库（含 salt），但内存扫描报 `0 unique keys`，所有库都无法解密。

## 2. 修复来源（三层合并）

| 来源 | 内容 | 在本仓库中的角色 |
|---|---|---|
| 上游 [PR #22](https://github.com/huohuoer/wechat-cli/pull/22) | Windows 版 Config.Cipher 扫描 + `verify_enc_key` 增加 HMAC-SHA1 | 提供思路与 Windows 路径修复（`scanner_windows.py`） |
| 上游 [PR #23](https://github.com/huohuoer/wechat-cli/pull/23) | 同思路的 macOS 移植（mach_vm_read 版 C 扫描器） | 被下一项取代：其对象偏移沿用 Windows（`+0x88`），在 macOS 上找不到引用 |
| [sunfeihu007/wechat-cli](https://github.com/sunfeihu007/wechat-cli) commit `ff86fb1` | **macOS 4.1.13 真机验证**的偏移修正 + Python 层 HMAC 把关 | macOS 路径的最终实现（C 源码 + `scanner_macos.py` + 测试） |

关键差异：macOS 的 WCDB 配置对象中 blob 指针位于 `+0x68` 或 `+0x90`（Windows 是 `+0x88`），
扫描器现在对三种布局逐一尝试；同时放宽了 `is_probable_key` 的熵启发（原"≥15 个不同字符"会误杀
合法随机密钥），改为全部候选交给 Python 层用数据库页 1 的 HMAC 校验，只有通过校验的密钥才会保存。

## 3. 修复后的提取流程

1. **收集数据库**：遍历微信 `db_storage`，读每个 `.db` 首页前 16 字节得到 salt；
2. **定位 Config.Cipher**：在全部可读内存映射中搜索名字符串
   `com.Tencent.WCDB.Config.Cipher`（只读段）；再在内存中搜索
   `{指向名字的指针, 名字长度}` 的 16 字节引用模式；
3. **解码 blob**：沿引用结构找到配置对象，按 `0x68 / 0x90 / 0x88` 三种布局读取
   `{data_ptr, data_len}`，取出 blob 后用固定 32 字节掩码循环 XOR 解码；
4. **提取候选**：在解码结果中匹配 `x'<64位hex><32位hex>'`，得到 key+salt 候选；
5. **Python 校验**（`scanner_macos.py`）：每个候选对目标数据库页 1 做
   HMAC-SHA1（新）/ HMAC-SHA512（旧）校验（`keys/common.py::verify_enc_key`）；
6. **合并保存**：通过校验的新密钥与已保存的旧密钥合并，写临时文件后
   `os.replace` 原子落盘；扫描失败/校验失败时**不改动**已有密钥文件。

## 4. 本机构建与测试

仓库自带源码（`wechat_cli/bin/find_all_keys_macos.c`）与预编译 arm64 二进制。
如需自行重建（推荐，避免使用来路不明的预编译产物）：

```bash
cd wechat_cli/bin
clang -O2 -Wall -arch arm64 -o find_all_keys_macos.arm64 find_all_keys_macos.c -framework Foundation
```

回归测试（两套都必须通过）：

```bash
# C 合成布局测试（0x68/0x90/0x88 三种配置对象布局）
cc -O2 -Wall -Wextra -Werror tests/test_config_cipher.c -o /tmp/test_config_cipher \
  -framework Foundation && /tmp/test_config_cipher

# Python 单元测试（HMAC 校验、失败保留旧密钥、原子保存）
python3 -m unittest discover -s tests -v
```

实测记录（2026-10-24，macOS 26.5 / 微信 4.1.15 / M 系列）：`init --force` 提取
**21/21** 个数据库密钥，全部通过 HMAC 校验；`sessions` / `history` / `search` 均正常解密。

## 5. 新机器安装（Apple Silicon Mac）

前置：macOS ≥ 26.3.1，微信 Mac 已安装、已启动并登录（扫码或手机确认）。

```bash
# 方式一：uv（无需自建虚拟环境）
uv tool install "wechat-cli @ git+https://github.com/Willing-Xyz/wechat-cli.git@main"

# 方式二：pip（建议在虚拟环境中）
python3 -m pip install --upgrade "git+https://github.com/Willing-Xyz/wechat-cli.git@main"
```

然后：

```bash
wechat-cli init --force
```

说明：

- 第一次运行若报 `task_for_pid failed`，工具会**自动给微信 ad-hoc 重签名**（保留原有
  entitlements，仅加 `get-task-allow`，不影响正常使用，但可能影响微信自动更新）。此时需要
  **完全退出微信 → 重新打开并登录 → 再次执行同一条命令**；
- 重签名后通常**无需 sudo**（同用户 + 可调试目标即可读内存）；个别系统如提示权限不足，
  用 `sudo "$(command -v wechat-cli)" init --force`；
- 若终端（运行 wechat-cli 的 app）已在"系统设置 → 隐私与安全性 → 完全磁盘访问权限"中授权，
  初次扫描会更顺畅（未授权时部分系统也会正常工作）；
- 密钥与配置保存在 `~/.wechat-cli/{config.json,all_keys.json}`（权限 0600）；
- 微信升级/重装后密钥仍在，重新执行 `wechat-cli init --force` 刷新即可。

常用命令（默认输出 JSON，便于 Agent 消费）：

```bash
wechat-cli sessions --limit 10
wechat-cli history "联系人或群名" --limit 20
wechat-cli unread
wechat-cli search "关键词" --chat "群名"
wechat-cli export "联系人" --format markdown
```

## 6. 本仓库的合并提交清单

```
6d18b19 Merge sunfeihu007 fix: macOS WeChat 4.1.13 Config.Cipher layouts
        (0x68/0x90/0x88) + HMAC-verified key merge
e69995b Rebuild find_all_keys_macos.arm64 from merged source (PR #23)
af1b8a9 Merge PR #23: macOS WeChat 4.1.x Config.Cipher key extraction
        (fast-forward) Merge PR #22: WeChat 4.1.x key extraction
        (Windows Config.Cipher scan + HMAC-SHA1 verify)
```

安全提示：本工具仅读取本机微信数据库，不联网传输、不自动化操作微信，仅供个人学习研究。
