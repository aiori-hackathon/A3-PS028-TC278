# HappyLab: shortcuts for the existing scripts. Every target only calls a script that already
# exists; read the script before running a target that needs sudo (lab-up, lab-down, run).
#
#   make check        report what install.sh would do; changes nothing
#   make setup        scripts/install.sh: apt and pip dependencies, .venv
#   make test         scripts/test.sh (pass pytest arguments with ARGS="-k csv")
#   make lab-up       sudo src/lab/setup.sh: build and verify the hl- namespaces
#   make lab-down     sudo src/lab/teardown.sh: remove them and verify nothing is left
#   make run          sudo run_matrix.py: the full matrix (ARGS="--dry-run", "--only S1:curl", "--from 5")
#   make report       summarise.py: tables, interpretation and summary.json (DATASET=name for a manifest)
#   make dashboard    dashboard.py: data/generated/summary/dashboard.html (DATASET=name for a manifest)
#   make csv          export_csv.py: the dataset as CSV (OUT=file, default stdout; DATASET=name)
#   make demo         scripts/demo.sh: live demo, one run (SCENARIO=S1 CLIENT=curl), into data/demo/ only
#   make demo-check   scripts/demo_check.sh: venue pre-flight for make demo; changes nothing
#   make demo-isolation-check   fingerprint, make demo twice, fingerprint: every summary byte-identical
#
# Python always runs without PYTHONPATH and LD_LIBRARY_PATH (a ROS shell sets both), and sudo is
# plain sudo, never sudo -E.

PY      := env -u PYTHONPATH -u LD_LIBRARY_PATH .venv/bin/python
ARGS    ?=
SCENARIO ?= S1
CLIENT   ?= curl
DATASET ?=
OUT     ?=
dataset_arg := $(if $(DATASET),--dataset $(DATASET))

.DEFAULT_GOAL := help
.PHONY: help check setup test lab-up lab-down run report dashboard csv demo demo-check demo-isolation-check

help:
	@sed -n '4,16p' Makefile | sed 's/^# \{0,1\}//'

check:
	scripts/install.sh --check

setup:
	scripts/install.sh

test:
	scripts/test.sh $(ARGS)

lab-up:
	sudo src/lab/setup.sh

lab-down:
	sudo src/lab/teardown.sh

run:
	sudo $(PY) src/runner/run_matrix.py $(ARGS)

report:
	$(PY) src/analysis/summarise.py $(dataset_arg) $(ARGS)

dashboard:
	$(PY) src/analysis/dashboard.py $(dataset_arg) $(ARGS)

csv:
	$(PY) src/analysis/export_csv.py $(dataset_arg) $(if $(OUT),--out $(OUT)) $(ARGS)

# make demo runs as your user and calls sudo itself (once with a prompt, then sudo -n only).
demo:
	SCENARIO=$(SCENARIO) CLIENT=$(CLIENT) scripts/demo.sh

demo-check:
	scripts/demo_check.sh

FP := data/demo/isolation
demo-isolation-check:
	$(PY) src/analysis/summary_fingerprint.py snapshot $(FP)/before.json
	DEMO_OPEN=0 SCENARIO=$(SCENARIO) CLIENT=$(CLIENT) scripts/demo.sh
	DEMO_OPEN=0 SCENARIO=$(SCENARIO) CLIENT=$(CLIENT) scripts/demo.sh
	$(PY) src/analysis/summary_fingerprint.py snapshot $(FP)/after.json
	$(PY) src/analysis/summary_fingerprint.py compare $(FP)/before.json $(FP)/after.json
