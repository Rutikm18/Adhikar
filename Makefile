.PHONY: demo eval test build-ui docker-build docker-up docker-down docker-logs

demo:
	uvicorn app.main:app --reload --port 8018

docker-build:
	docker build -t adhikar:latest .

docker-up:
	docker compose up --build -d
	@echo "Adhikar on http://127.0.0.1:8018 (docker compose logs -f to follow)"

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

eval:
	python3 evals/run_evals.py

build-ui:
	node tools/build_ui.mjs

test:
	python3 -m unittest discover -s tests -v
	python3 evals/test_no_direct_sdk.py
	python3 evals/run_evals.py
	HARNESS_BACKEND=mock python3 evals/test_harness_contract.py
