"""macOS 密钥提取 — 通过 C 二进制扫描微信进程内存"""

import os
import platform
import plistlib
import subprocess
import sys
import tempfile

from .common import verify_enc_key


def _find_binary():
    """查找对应架构的 C 二进制。"""
    machine = platform.machine()
    if machine == "arm64":
        name = "find_all_keys_macos.arm64"
    elif machine == "x86_64":
        name = "find_all_keys_macos.x86_64"
    else:
        raise RuntimeError(f"不支持的 macOS 架构: {machine}")

    # PyInstaller 运行时：从临时解压目录查找
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    bin_path = os.path.join(base, "wechat_cli", "bin", name)
    if os.path.isfile(bin_path):
        return bin_path

    # fallback: 直接在 bin/ 下
    bin_path = os.path.join(base, "bin", name)
    if os.path.isfile(bin_path):
        return bin_path

    raise RuntimeError(
        f"找不到密钥提取二进制: {bin_path}\n"
        "请确认安装包完整"
    )


def _get_original_entitlements(app_path):
    """提取 app 当前的签名 entitlements，返回 dict 或 None。"""
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", app_path],
            capture_output=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout:
            return plistlib.loads(result.stdout)
    except Exception:
        pass
    return None


def _build_entitlements_xml(app_path):
    """构建 entitlements：保留原有权限 + 添加 get-task-allow。"""
    entitlements = _get_original_entitlements(app_path)
    if entitlements is None:
        entitlements = {}

    entitlements["com.apple.security.get-task-allow"] = True

    return plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)


def _resign_wechat():
    """Re-sign WeChat: 保留原有 entitlements，仅添加 get-task-allow。"""
    wechat_paths = [
        "/Applications/WeChat.app",
        os.path.expanduser("~/Applications/WeChat.app"),
    ]
    wechat_app = None
    for p in wechat_paths:
        if os.path.isdir(p):
            wechat_app = p
            break

    if wechat_app is None:
        return False, "未找到 WeChat.app（已搜索 /Applications 和 ~/Applications）"

    print(f"\n[*] 检测到 task_for_pid 权限不足，正在对微信重新签名...")
    print(f"    目标: {wechat_app}")

    # 提取并合并 entitlements
    try:
        ent_data = _build_entitlements_xml(wechat_app)
    except Exception as e:
        return False, f"提取微信原始权限失败: {e}"

    ent_fd, ent_path = tempfile.mkstemp(suffix=".plist")
    try:
        with os.fdopen(ent_fd, "wb") as f:
            f.write(ent_data)

        result = subprocess.run(
            ["codesign", "--force", "--sign", "-", "--entitlements", ent_path, wechat_app],
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        os.unlink(ent_path)

    if result.returncode != 0:
        return False, f"codesign 失败: {result.stderr.strip()}"

    print("[+] 签名完成（已保留微信原有权限，仅添加调试访问权限）。")
    print("[+] 请重新启动微信后再执行 init。")
    print("[!] 注意：如果微信自动更新，可能需要重新签名。")
    return True, None


def extract_keys(db_dir, output_path, pid=None):
    """通过 C 二进制提取 macOS 微信数据库密钥。

    C 二进制在私有临时目录运行，自动发现本机微信数据库。
    候选密钥必须通过所选账号数据库的 HMAC 校验才会保存。

    Args:
        db_dir: 微信 db_storage 目录
        output_path: all_keys.json 输出路径
        pid: 可选微信进程号；默认由 C 二进制自动检测

    Returns:
        dict: salt_hex -> enc_key_hex 映射
    """
    import json

    binary = _find_binary()

    if not os.path.isdir(db_dir):
        raise RuntimeError(f"微信数据目录不存在: {db_dir}")

    print(f"[+] 使用 C 二进制提取密钥: {binary}")
    try:
        # Isolate output from previous scans. The C helper discovers account
        # databases independently of its working directory.
        with tempfile.TemporaryDirectory(prefix="wechat-key-scan-") as work_dir:
            result = subprocess.run(
                [binary] + ([str(pid)] if pid is not None else []),
                cwd=work_dir,
                capture_output=True,
                text=True,
                timeout=120,
            )
            c_output = os.path.join(work_dir, "all_keys.json")
            keys_data = None
            if result.returncode == 0 and os.path.exists(c_output):
                try:
                    with open(c_output, encoding="utf-8") as f:
                        keys_data = json.load(f)
                except (ValueError, OSError) as e:
                    raise RuntimeError("密钥扫描结果格式无效，原有密钥未修改") from e
    except subprocess.TimeoutExpired:
        raise RuntimeError("密钥提取超时（120s）")
    except PermissionError:
        raise RuntimeError(
            f"无法执行 {binary}\n"
            "请确保文件有执行权限: chmod +x " + binary
        )

    # 打印 C 二进制的输出
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    # 检测 task_for_pid 失败 → 尝试 re-sign
    combined_output = (result.stdout or "") + (result.stderr or "")
    if "task_for_pid" in combined_output:
        print("\n[!] task_for_pid 失败：macOS 安全策略阻止了进程内存访问。")
        print("[!] 需要对微信重新签名以允许调试访问（不影响微信正常功能）。")

        ok, err = _resign_wechat()
        if ok:
            raise RuntimeError(
                "已对微信重新签名（保留原有权限）。请执行以下步骤后重试：\n"
                "  1. 退出微信（完全退出，不是最小化）\n"
                "  2. 重新打开微信并登录\n"
                "  3. 再次执行: sudo wechat-cli init --force"
            )
        else:
            # 手动命令也需要保留原有权限
            raise RuntimeError(
                f"自动签名失败: {err}\n"
                "请手动执行以下命令后重试：\n"
                "  # 1. 提取微信原有权限\n"
                "  codesign -d --entitlements wechat_ent.plist /Applications/WeChat.app\n"
                "  # 2. 用 PlistBuddy 添加 get-task-allow\n"
                '  /usr/libexec/PlistBuddy -c "Add :com.apple.security.get-task-allow bool true" wechat_ent.plist\n'
                "  # 3. 重新签名\n"
                "  codesign --force --sign - --entitlements wechat_ent.plist /Applications/WeChat.app\n"
                "  # 4. 清理\n"
                "  rm wechat_ent.plist\n"
                "然后重启微信，再执行: sudo wechat-cli init --force"
            )

    if result.returncode != 0:
        raise RuntimeError(f"密钥扫描程序退出（状态码 {result.returncode}），原有密钥未修改")
    if not isinstance(keys_data, dict) or not keys_data:
        raise RuntimeError("未提取到密钥，原有密钥未修改；请确认已登录及微信版本兼容性")

    def verified_entries(entries):
        valid = {}
        if not isinstance(entries, dict):
            return valid
        root = os.path.realpath(db_dir)
        for rel, info in entries.items():
            if not isinstance(info, dict) or not isinstance(info.get("enc_key"), str):
                continue
            path = os.path.realpath(os.path.join(root, rel))
            if os.path.commonpath([root, path]) != root:
                continue
            try:
                key = bytes.fromhex(info["enc_key"])
                with open(path, "rb") as f:
                    page = f.read(4096)
                if len(key) != 32 or len(page) != 4096 or not verify_enc_key(key, page):
                    continue
            except (OSError, ValueError):
                continue
            valid[rel] = {"enc_key": key.hex(), "salt": page[:16].hex()}
        return valid

    candidates = verified_entries(keys_data)
    if not candidates:
        raise RuntimeError("没有候选密钥通过数据库 HMAC 校验，原有密钥未修改")
    existing = {}
    if os.path.exists(output_path):
        with open(output_path, encoding="utf-8") as f:
            existing = verified_entries(json.load(f))
    existing.update(candidates)

    parent = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(parent, exist_ok=True)
    fd, staged = tempfile.mkstemp(prefix=".keys-", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(staged, output_path)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)
    key_map = {info["salt"]: info["enc_key"] for info in existing.values()}
    print(f"\n[+] HMAC 校验通过 {len(candidates)} 个，本地共保存 {len(existing)} 个数据库密钥")
    return key_map
