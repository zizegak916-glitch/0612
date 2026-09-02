.PHONY: test lint cli desktop android package clean

test:
	python3 -m unittest discover -s tests -v

lint:
	python3 -m compileall -q src tests scripts

cli:
	PYTHONPATH=src python3 -m ipbatch_inspector --help

desktop:
	PYTHONPATH=src python3 -m ipbatch_inspector.desktop

android:
	cd apps/android && ./build.sh

package:
	python3 -m pip install --upgrade build
	python3 -m build

clean:
	python3 -c "import pathlib,shutil; [shutil.rmtree(p,ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"
	rm -rf dist build *.egg-info apps/android/build apps/android/.toolchain
