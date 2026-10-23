# check_patch.py -- 检验 VirusWiseApp 的方法是否都在类体里
import ast, importlib.util, os, sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
CLASS_FILE = os.path.join(ROOT, "ui", "app.py")
LEGACY_FILE = os.path.join(ROOT, "legacy_patch.py")

MODULE_LEVEL_OK = {
    "setup_exception_handler", "safe_get_base_dir", "is_admin",
    "collect_files", "record_processes_for_30_seconds", "elevate_if_needed", "main",
}
MUST_SKIP = {"handle_system_write"}


def body_defined(path, cls="VirusWiseApp"):
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == cls:
            return {n.name: n.lineno for n in node.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    return {}


def main():
    problems = []
    in_body = body_defined(CLASS_FILE)
    print(f"[A] VirusWiseApp 类体内定义的方法: {len(in_body)}")

    spec = importlib.util.spec_from_file_location("ui.app", CLASS_FILE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ui.app"] = mod
    spec.loader.exec_module(mod)
    App = mod.VirusWiseApp

    import customtkinter as ctk
    patched = []
    for name, obj in App.__dict__.items():
        if not callable(obj) or name.startswith("__"):
            continue
        if name in in_body or hasattr(ctk.CTk, name):
            continue
        patched.append((name, getattr(obj, "__module__", "?"),
                        getattr(obj, "__qualname__", "?")))
    print(f"[B] 类体之外挂到 VirusWiseApp 上的可调用成员: {len(patched)}")
    for name, m, q in sorted(patched):
        print(f"    PATCHED  {name:<34} <- {m}:{q}")
        problems.append(f"{name} 不是类体定义的")

    if os.path.exists(LEGACY_FILE):
        tree = ast.parse(open(LEGACY_FILE, encoding="utf-8").read())
        funcs = {n.name: n.lineno for n in tree.body
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        print(f"\n[C] legacy_patch.py 顶层函数: {len(funcs)}")
        for name, ln in sorted(funcs.items()):
            if name in MODULE_LEVEL_OK or name in MUST_SKIP:
                continue
            if name not in in_body:
                print(f"    MISSING  {name}  (legacy_patch.py:{ln})")
                problems.append(f"{name} 未迁移")
        for name in in_body:
            if name in funcs:
                print(f"    SHADOW   {name}  类体与 legacy 顶层同名")
    else:
        print("\n[C] legacy_patch.py 已不存在")

    print()
    if problems:
        print(f"❌ 有 {len(problems)} 个问题")
        return 1
    print("✅ 所有方法均已在 VirusWiseApp 类体内定义")
    return 0


if __name__ == "__main__":
    sys.exit(main())
