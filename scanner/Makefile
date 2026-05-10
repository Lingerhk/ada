SHELL := /bin/bash

PYTHON ?= python3
PY2SEC_PYTHON ?= python3.7
PY2SEC_DIR ?= .build/py2sec
PY2SEC_DOWNLOAD_URL ?= https://github.com/cckuailong/py2sec
PLUGINS_DIR ?= plugins
PLUGIN_CATEGORIES ?= baseline,leak,weakpwd
PLUGIN_MODE ?= missing
PLUGIN_IDS ?=
PLUGIN_ENC_OUT ?= worker/plugin_enc.tar.gz
VENV_ENC_OUT ?= worker/venv_enc.tar.gz
PYLIBS_SITE_PACKAGES ?= pylibs/site-packages
PYLIBS_PACKAGES ?= utillib utillib-1.0.0.dist-info
PYLIBS_LEGACY_PACKAGES ?= common config model
VENV_PACKAGE_WORKDIR ?= .build/venv-package
VENV_SITE_PACKAGES ?= $(VENV_PACKAGE_WORKDIR)/.venv/lib/python3.7/site-packages
SCANNER_PKG_KEY ?= G0pRA3dhZcdQDF1S
DOCKER ?= docker
DOCKER_PYSRC_IMAGE ?= ada_scanner_pysrc:py37
DOCKER_PYSRC_FILE ?= ../script/docker/scanner/Dockerfile.pysrc
DOCKER_PYSRC_CONTEXT ?= ../script/docker/scanner
REPO_ROOT ?= $(abspath ../..)
CYTHON_VERSION ?= 0.29.27
PIP_INDEX_URL ?= https://mirrors.aliyun.com/pypi/simple
PIP_TRUSTED_HOST ?= mirrors.aliyun.com

PLUGIN_ARGS := --plugins-dir $(PLUGINS_DIR) \
	--py2sec-dir $(PY2SEC_DIR) \
	--python $(PY2SEC_PYTHON) \
	--categories $(PLUGIN_CATEGORIES) \
	--mode $(PLUGIN_MODE)

ifneq ($(strip $(PLUGIN_IDS)),)
PLUGIN_ARGS += --plugins $(PLUGIN_IDS)
endif

.PHONY: help
help:
	@echo "Usage:"
	@echo "  make compile-plugins              Compile plugins missing main.so"
	@echo "  make compile-plugins-docker       Build Python 3.7 image and compile missing plugins"
	@echo "  make compile-plugins-dry-run      Show plugins that would be compiled"
	@echo "  make compile-plugins-all          Rebuild all plugin .so files"
	@echo "  make package-plugins              Repack plugins as worker/plugin_enc.tar.gz"
	@echo "  make package-venv                 Repack venv with pylibs/site-packages"
	@echo "  make package-runtime              Repack plugin and venv payloads"
	@echo "  make compile-and-package          Compile missing plugins, then repack payloads"
	@echo "  make compile-and-package-docker   Docker compile missing plugins, then repack payloads"
	@echo ""
	@echo "Variables:"
	@echo "  PY2SEC_PYTHON=/path/to/python3.7"
	@echo "  PY2SEC_DIR=.build/py2sec"
	@echo "  PLUGIN_IDS=baseline/plugin_1110,leak/plugin_112"
	@echo "  PYLIBS_PACKAGES='utillib utillib-1.0.0.dist-info'"

.PHONY: check-py2sec
check-py2sec:
	@if [ ! -f "$(PY2SEC_DIR)/py2sec.py" ] || [ ! -f "$(PY2SEC_DIR)/py2sec_build.py.template" ]; then \
		echo "py2sec not found or incomplete: $(PY2SEC_DIR)"; \
		echo "先下载 $(PY2SEC_DOWNLOAD_URL) 到 scanner/.build/py2sec"; \
		exit 1; \
	fi

.PHONY: compile-plugins
compile-plugins: check-py2sec
	$(PYTHON) tools/compile_plugins.py $(PLUGIN_ARGS)

.PHONY: compile-plugins-dry-run
compile-plugins-dry-run:
	$(PYTHON) tools/compile_plugins.py $(PLUGIN_ARGS) --dry-run

.PHONY: compile-plugins-all
compile-plugins-all:
	$(MAKE) compile-plugins PLUGIN_MODE=all

.PHONY: docker-py37-image
docker-py37-image:
	$(DOCKER) build --network=host -f $(DOCKER_PYSRC_FILE) -t $(DOCKER_PYSRC_IMAGE) $(DOCKER_PYSRC_CONTEXT)

.PHONY: compile-plugins-docker
compile-plugins-docker: check-py2sec docker-py37-image
	$(DOCKER) run --rm --network=host \
		-u "$$(id -u):$$(id -g)" \
		-e HOME=/tmp \
		-e PYTHONDONTWRITEBYTECODE=1 \
		-v $(REPO_ROOT):/src \
		-w /src/ada/scanner \
		$(DOCKER_PYSRC_IMAGE) \
		bash -lc 'python3.7 -m venv /tmp/py37 && \
			. /tmp/py37/bin/activate && \
			python -m pip install -i $(PIP_INDEX_URL) --trusted-host $(PIP_TRUSTED_HOST) Cython==$(CYTHON_VERSION) && \
			make compile-plugins PY2SEC_PYTHON=/tmp/py37/bin/python PLUGIN_CATEGORIES=$(PLUGIN_CATEGORIES) PLUGIN_MODE=$(PLUGIN_MODE) PLUGIN_IDS=$(PLUGIN_IDS)'

.PHONY: package-plugins
package-plugins:
	tar -czf - plugins | /usr/bin/openssl des3 -salt -k $(SCANNER_PKG_KEY) -out $(PLUGIN_ENC_OUT)

.PHONY: package-venv
package-venv:
	rm -rf $(VENV_PACKAGE_WORKDIR)
	mkdir -p $(VENV_PACKAGE_WORKDIR)
	/usr/bin/openssl des3 -d -k $(SCANNER_PKG_KEY) -salt -in $(VENV_ENC_OUT) | tar -C $(VENV_PACKAGE_WORKDIR) -xzf -
	test -d $(VENV_SITE_PACKAGES)
	for pkg in $(PYLIBS_LEGACY_PACKAGES); do \
		rm -rf "$(VENV_SITE_PACKAGES)/$$pkg"; \
	done
	for pkg in $(PYLIBS_PACKAGES); do \
		test -e "$(PYLIBS_SITE_PACKAGES)/$$pkg"; \
		rm -rf "$(VENV_SITE_PACKAGES)/$$pkg"; \
		cp -a "$(PYLIBS_SITE_PACKAGES)/$$pkg" "$(VENV_SITE_PACKAGES)/"; \
	done
	tar -C $(VENV_PACKAGE_WORKDIR) -czf - .venv | /usr/bin/openssl des3 -salt -k $(SCANNER_PKG_KEY) -out $(VENV_ENC_OUT).tmp
	mv $(VENV_ENC_OUT).tmp $(VENV_ENC_OUT)
	rm -rf $(VENV_PACKAGE_WORKDIR)

.PHONY: package-runtime
package-runtime: package-plugins package-venv

.PHONY: compile-and-package
compile-and-package: compile-plugins package-runtime

.PHONY: compile-and-package-docker
compile-and-package-docker: compile-plugins-docker package-runtime

.DEFAULT_GOAL := help
