.PHONY: test test-cov perf-test demo lint clean

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=micropki --cov-report=term-missing --cov-report=html

perf-test:
	pytest tests/test_performance.py -v --run-perf -s

demo:
	python demo/demo.py

lint:
	python -m py_compile micropki/cli.py
	python -m py_compile micropki/ca.py

clean:
	rm -rf demo_pki demo_secrets htmlcov .coverage .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
