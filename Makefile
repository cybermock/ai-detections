.PHONY: test lint build clean

test:
	python -m pytest tests/ -v

lint:
	ruff check tests/

build:
	bash deploy/build.sh

clean:
	rm -rf build/ dist/ *.spl
	find . -type d -name __pycache__ -exec rm -rf {} +
