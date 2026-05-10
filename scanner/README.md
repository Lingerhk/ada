# Scanner Build And Plugin Packaging

## Runtime Layout

The scanner binary embeds two encrypted runtime archives:

- `worker/plugin_enc.tar.gz`: scanner plugins only. It expands to `/var/lib/scada/.sc/plugins`.
- `worker/venv_enc.tar.gz`: Python runtime and shared libraries. It expands to `/var/lib/scada/.venv`.

Plugin code is loaded by the Go scanner through Python 3.7:

```text
plugins.<category>.plugin_<id>.main
```

The Python import path is:

```text
/var/lib/scada/.sc:/var/lib/scada/.venv/lib/python3.7/site-packages
```

## Source Directories

- `plugins/`: plugin directories and compiled `main.so` files.
- `pylibs/site-packages/utillib`: shared scanner helper package.
- `pylibs/site-packages/utillib-1.0.0.dist-info`: package metadata for the shared helper package.

Keep shared Python packages under `pylibs/site-packages`. Do not add top-level runtime packages to `plugin_enc.tar.gz`; that archive should contain `plugins/` only.

## Compile Missing Plugin `.so`

`py2sec` is expected under the scanner-local build directory:

```bash
cd /home/adadmin/adaegis/ada/scanner
rm -rf .build/py2sec
git clone https://github.com/cckuailong/py2sec .build/py2sec
```

The Makefile fails before compiling when `.build/py2sec/py2sec.py` or
`.build/py2sec/py2sec_build.py.template` is missing.

Use the Docker-based Python 3.7 flow when the host does not have a compatible Python 3.7/Cython environment:

```bash
cd /home/adadmin/adaegis/ada/scanner
make compile-plugins-docker
```

This builds from `script/docker/scanner/Dockerfile.pysrc`, installs `Cython==0.29.27`, and compiles only plugins missing `main.so` by default. Existing `.py` files are not modified.

Useful variants:

```bash
make compile-plugins-dry-run
make compile-plugins PLUGIN_IDS=baseline/plugin_1110,leak/plugin_112 PY2SEC_PYTHON=/path/to/python3.7
make compile-plugins-all PY2SEC_PYTHON=/path/to/python3.7
```

## Repack Runtime Archives

After plugin or shared-library changes:

```bash
cd /home/adadmin/adaegis/ada/scanner
make package-runtime
```

This runs:

- `package-plugins`: encrypts `plugins/` into `worker/plugin_enc.tar.gz`.
- `package-venv`: decrypts `worker/venv_enc.tar.gz`, removes legacy top-level `common/config/model` packages, overlays `PYLIBS_PACKAGES`, and re-encrypts it.

By default only these packages are overlaid into the Python runtime:

```bash
PYLIBS_PACKAGES="utillib utillib-1.0.0.dist-info"
```

For new plugin development in a Docker Python 3.7 environment:

```bash
make compile-and-package-docker
```

## Rebuild Scanner

From the repo root:

```bash
cd /home/adadmin/adaegis/ada
make scanner
```

`script/docker/build.sh` also runs `make -C scanner package-runtime` before rebuilding the scanner image.

## Test Validation Checklist

After deploying `ada_scanner` to test `192.168.7.2`, verify:

```bash
docker inspect ada_scanner --format 'RestartCount={{.RestartCount}} Status={{.State.Status}}'
docker exec ada_scanner bash -lc 'find /var/lib/scada/.sc/plugins -mindepth 3 -maxdepth 3 -name package.json | wc -l'
docker exec ada_scanner bash -lc 'find /var/lib/scada/.sc/plugins -mindepth 3 -maxdepth 3 -name main.so | wc -l'
docker exec ada_scanner bash -lc 'test -f /var/lib/scada/.venv/lib/python3.7/site-packages/utillib/common/util.py && test ! -d /var/lib/scada/.venv/lib/python3.7/site-packages/model && echo venv_runtime_ok'
docker exec ada_scanner bash -lc 'tail -100 /home/adadmin/logs/scanner.log'
```

Expected startup log:

```text
registered plugins=179; templates refreshed
scanner(scgo) starting celery workers=8
```

MongoDB should show:

```text
tb_scan_plugin: 179
baseline template plugins: 166
leak template plugins: 12
weakpwd template plugins: 1
```
