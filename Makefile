.PHONY: install run test lint docker

install:
	python3 -m venv .venv && . .venv/bin/activate && python -m pip install -r requirements-dev.txt

run:
	. .venv/bin/activate && python -m streamlit run app.py --server.port 8501

test:
	. .venv/bin/activate && python -m pytest -q

lint:
	. .venv/bin/activate && python -m ruff check .

docker:
	docker compose up --build
