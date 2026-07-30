.PHONY: demo eval test

demo:
	uvicorn app.main:app --reload --port 8018

eval:
	python3 evals/run_evals.py

test:
	python3 -m unittest discover -s tests -v
	python3 evals/test_no_direct_sdk.py
	python3 evals/run_evals.py
