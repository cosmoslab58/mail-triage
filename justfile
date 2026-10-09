install:
    python3 -m venv venv && venv/bin/pip install -q -r requirements-dev.txt

test:
    venv/bin/python -m pytest -q

lint:
    venv/bin/ruff check .

# classify the last N inbox messages of one account and print, no side effects
try account n="10":
    venv/bin/python triage.py try {{account}} {{n}}
