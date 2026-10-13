from causalfence import ci
def test_safe_template_passes(tmp_path):
    out = tmp_path / "c.md"
    code = ci.main(["--template", "infra/template.yaml", "--comment", str(out)])
    text = out.read_text(encoding="utf-8")
    assert code == 0
    assert ci.MARKER in text and "PASS" in text
def test_broken_template_fails_with_evidence(tmp_path):
    out = tmp_path / "c.md"
    code = ci.main(["--template", "infra/template.yaml", "--param", "AuthMode=broken",
                    "--comment", str(out)])
    text = out.read_text(encoding="utf-8")
    assert code == 1
    assert "FAIL - merge blocked" in text
    assert "AUTH_BYPASS" in text and "infra/template.yaml" in text
    assert "Copy-paste fix" in text
def test_demo_templates_fail_with_their_rule():
    for path, rule in [("infra/demo-stacks/urlopen-app.yaml", "LAMBDA_URL_OPEN"),
                       ("infra/demo-stacks/wildcard-app.yaml", "OVERBROAD_IAM")]:
        result, verdict = ci.scan_template(path)
        assert [f.rule for f in result.findings] == [rule]
def test_missing_template_is_an_error(tmp_path):
    out = tmp_path / "c.md"
    code = ci.main(["--template", "nope.yaml", "--comment", str(out)])
    assert code == 2
    assert "Could not scan" in out.read_text(encoding="utf-8")
