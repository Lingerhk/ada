# Scanner runtime payloads

`make -C scanner package-runtime` writes the encrypted Python runtime payloads
here before the scanner binary is built:

- `plugin_enc.tar.gz` - compiled scanner plugins
- `venv_enc.tar.gz` - Python virtualenv used to run them

Both files are git-ignored. The whole directory is embedded into the scanner
binary (`//go:embed assets`); when the payloads are missing the binary still
builds, and `scanner` reports at startup that the runtime is not bundled.
