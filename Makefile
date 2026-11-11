reproduce:
	python scripts/reproduce.py

test:
	python -m pytest -q

.PHONY: reproduce test
