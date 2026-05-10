#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PY2SEC_DOWNLOAD_URL = "https://github.com/cckuailong/py2sec"


def csv_list(value):
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def scanner_root():
    return Path(__file__).resolve().parents[1]


def resolve_path(root, value):
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def iter_plugin_dirs(plugins_dir, categories):
    if categories == ["all"]:
        category_dirs = sorted(path for path in plugins_dir.iterdir() if path.is_dir())
    else:
        category_dirs = [plugins_dir / category for category in categories]

    for category_dir in category_dirs:
        if not category_dir.is_dir():
            continue
        for plugin_dir in sorted(category_dir.iterdir()):
            if plugin_dir.is_dir() and (plugin_dir / "package.json").is_file():
                yield plugin_dir


def normalize_selector(selector):
    selector = selector.strip().strip("/")
    if not selector:
        return selector
    parts = selector.split("/")
    if len(parts) == 1:
        return parts[0]
    return "/".join(parts[-2:])


def select_plugins(candidates, plugins_dir, selectors):
    if not selectors:
        return candidates

    wanted = {normalize_selector(item) for item in selectors}
    selected = []
    for plugin_dir in candidates:
        rel = plugin_dir.relative_to(plugins_dir).as_posix()
        if rel in wanted or plugin_dir.name in wanted:
            selected.append(plugin_dir)
    return selected


def plugin_rel(plugin_dir, plugins_dir):
    return plugin_dir.relative_to(plugins_dir).as_posix()


def ensure_py2sec(py2sec_dir):
    required = [py2sec_dir / "py2sec.py", py2sec_dir / "py2sec_build.py.template"]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError(
            "invalid py2sec dir, missing: {missing}\n"
            "先下载 {url} 到 scanner/.build/py2sec".format(
                missing=", ".join(missing),
                url=PY2SEC_DOWNLOAD_URL,
            )
        )


def ensure_python(python_cmd):
    resolved = shutil.which(python_cmd) if not os.path.isabs(python_cmd) else python_cmd
    if not resolved or not Path(resolved).exists():
        raise RuntimeError(
            f"python executable not found: {python_cmd}. "
            "Use PY2SEC_PYTHON=/path/to/python3.7 when running make."
        )


def python_env(python_cmd):
    env = os.environ.copy()
    resolved = shutil.which(python_cmd) if not os.path.isabs(python_cmd) else python_cmd
    if resolved:
        env["PATH"] = str(Path(resolved).parent) + os.pathsep + env.get("PATH", "")
    return env


def copy_py2sec_tree(py2sec_dir, dst):
    ignore = shutil.ignore_patterns(
        "__pycache__",
        "*.pyc",
        "build",
        "tmp_build",
        "result",
        "tmp_py2sec_build.py",
    )
    shutil.copytree(py2sec_dir, dst, ignore=ignore)


def copy_plugin_tree(plugin_dir, dst):
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.c", "*.so", "*.pyd")
    shutil.copytree(plugin_dir, dst, ignore=ignore)


def compile_one(args, root, plugins_dir, py2sec_dir, plugin_dir, work_root):
    rel = plugin_rel(plugin_dir, plugins_dir)
    temp_dir = Path(tempfile.mkdtemp(prefix=rel.replace("/", "_") + "-", dir=work_root))
    keep_dir = args.keep_work
    try:
        temp_py2sec = temp_dir / "py2sec"
        copy_py2sec_tree(py2sec_dir, temp_py2sec)

        temp_plugin = temp_py2sec / "plugins" / rel
        temp_plugin.parent.mkdir(parents=True, exist_ok=True)
        copy_plugin_tree(plugin_dir, temp_plugin)

        cmd = [
            args.python,
            "py2sec.py",
            "-p",
            args.py2sec_py_arg,
            "-d",
            f"plugins/{rel}",
            "-q",
        ]
        proc = subprocess.run(
            cmd,
            cwd=str(temp_py2sec),
            env=python_env(args.python),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if proc.returncode != 0:
            keep_dir = True
            raise RuntimeError(
                "py2sec failed for {rel} with exit {code}\n{out}\nworkdir: {workdir}".format(
                    rel=rel,
                    code=proc.returncode,
                    out=proc.stdout,
                    workdir=temp_py2sec,
                )
            )

        result_plugin = temp_py2sec / "result" / "plugins" / rel
        if not result_plugin.is_dir():
            keep_dir = True
            raise RuntimeError(f"py2sec result missing for {rel}: {result_plugin}")

        so_files = sorted(result_plugin.rglob("*.so"))
        if not so_files:
            keep_dir = True
            raise RuntimeError(f"py2sec produced no .so files for {rel}")

        copied = []
        for so_file in so_files:
            dest = plugin_dir / so_file.relative_to(result_plugin)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(so_file, dest)
            copied.append(dest.relative_to(root).as_posix())

        if not (plugin_dir / "main.so").is_file():
            keep_dir = True
            raise RuntimeError(f"{rel} compiled but main.so is still missing")

        return copied
    finally:
        if not keep_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Compile scanner plugin .py files to .so with py2sec.")
    parser.add_argument("--plugins-dir", default="plugins")
    parser.add_argument("--py2sec-dir", default=".build/py2sec")
    parser.add_argument("--python", default="python3.7")
    parser.add_argument("--py2sec-py-arg", default="3")
    parser.add_argument("--categories", default="baseline,leak,weakpwd")
    parser.add_argument("--plugins", default="")
    parser.add_argument("--mode", choices=["missing", "all"], default="missing")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--keep-work", action="store_true")
    args = parser.parse_args()

    root = scanner_root()
    plugins_dir = resolve_path(root, args.plugins_dir)
    py2sec_dir = resolve_path(root, args.py2sec_dir)
    categories = csv_list(args.categories) or ["baseline", "leak", "weakpwd"]
    selectors = csv_list(args.plugins)

    if not plugins_dir.is_dir():
        print(f"plugins dir not found: {plugins_dir}", file=sys.stderr)
        return 2

    candidates = list(iter_plugin_dirs(plugins_dir, categories))
    selected = select_plugins(candidates, plugins_dir, selectors)
    if args.mode == "missing":
        selected = [path for path in selected if not (path / "main.so").is_file()]

    if args.dry_run:
        print(f"plugins_dir={plugins_dir}")
        print(f"py2sec_dir={py2sec_dir}")
        print(f"mode={args.mode}")
        print(f"selected={len(selected)}")
        for plugin_dir in selected:
            print(plugin_rel(plugin_dir, plugins_dir))
        return 0

    ensure_py2sec(py2sec_dir)
    ensure_python(args.python)
    work_root = root / ".build" / "py2sec-work"
    work_root.mkdir(parents=True, exist_ok=True)

    print(f"selected {len(selected)} plugin(s) for compile")
    total_so = 0
    for plugin_dir in selected:
        rel = plugin_rel(plugin_dir, plugins_dir)
        print(f"[py2sec] compiling {rel}")
        copied = compile_one(args, root, plugins_dir, py2sec_dir, plugin_dir, work_root)
        total_so += len(copied)
        for path in copied:
            print(f"  wrote {path}")

    print(f"done: compiled={len(selected)} so_files={total_so}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
