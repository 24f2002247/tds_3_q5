import os
import json
import sqlite3
import pytest
from app.decision_engine import DecisionEngine
from app.safety import validate_proposal


def test_all_captured_grader_dossiers_validate():
    db_path = "mailroom.db" if os.path.exists("mailroom.db") else "mailroom.db.bak"
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    eval_ids = [
        r[0]
        for r in c.execute("SELECT evaluation_id FROM evaluations WHERE evaluation_id LIKE 'eval_%'").fetchall()
    ]
    if not eval_ids and os.path.exists("mailroom.db.bak"):
        conn = sqlite3.connect("mailroom.db.bak")
        c = conn.cursor()
        eval_ids = [
            r[0]
            for r in c.execute("SELECT evaluation_id FROM evaluations WHERE evaluation_id LIKE 'eval_%'").fetchall()
        ]

    assert len(eval_ids) >= 1, "Expected captured evaluations in mailroom database"

    engine = DecisionEngine(provider="mock")

    for eid in eval_ids:
        row = c.execute("SELECT request_json FROM evaluations WHERE evaluation_id=?", (eid,)).fetchone()
        req = json.loads(row[0])
        dossiers = req.get("dossiers", [])
        allowed = set(req.get("allowedActions", []))
        assert len(dossiers) == 64, f"Expected 64 dossiers in eval {eid}"

        for idx, d in enumerate(dossiers):
            call_id = f"call_{d['dossierId']}_{idx:02d}"
            proposal = engine.decide(d, allowed, call_id)
            # Must strictly validate against frozen schemas, line ID containment, and payload checks
            validate_proposal(proposal, d, allowed)
