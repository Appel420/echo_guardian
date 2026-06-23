.PHONY: test verify checkpoint verify-checkpoint

test:
	PYTHONPATH=src pytest -q

verify:
	PYTHONPATH=src python tools/verify_audit.py examples/local-live-personal/audit_chain.jsonl

checkpoint:
	PYTHONPATH=src python tools/create_checkpoint.py examples/local-live-personal/audit_chain.jsonl examples/local-live-personal/checkpoint.json

verify-checkpoint:
	PYTHONPATH=src python tools/verify_checkpoint.py examples/local-live-personal/checkpoint.json
