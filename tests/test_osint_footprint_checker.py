from osint_footprint_checker.checks import run_checks, score

GOOD = {"security_txt": True,
        "headers": {"Strict-Transport-Security": "max-age=63072000",
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Content-Type-Options": "nosniff"},
        "dns": {"spf": True, "dmarc": True},
        "tls": {"versions": ["TLSv1.2", "TLSv1.3"], "days_to_expiry": 90}}

BAD = {"security_txt": False, "headers": {},
       "dns": {"spf": False, "dmarc": False, "dangling_cname": "old-app.herokuapp.com"},
       "tls": {"versions": ["TLSv1.0", "TLSv1.2"], "days_to_expiry": 5}}

def test_good_snapshot_scores_100():
    assert score(run_checks(GOOD)) == 100

def test_bad_snapshot_flags_highs():
    checks = {f.check for f in run_checks(BAD)}
    assert "dangling CNAME" in checks
    assert "TLS expiry" in checks

def test_bad_score_below_50():
    assert score(run_checks(BAD)) < 50

def test_missing_security_txt_flagged():
    assert any(f.check == "security.txt" for f in run_checks(BAD))

def test_old_tls_flagged():
    assert any(f.check == "TLS" for f in run_checks(BAD))
