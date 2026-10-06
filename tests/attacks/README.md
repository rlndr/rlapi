# Attack suite

One module per finding, named for its OWASP MCP Top 10 ID where it maps to one.

Each test here was written against **deliberately vulnerable code** and observed to
succeed at exploitation before the fix landed. After the fix it asserts the attack
fails. That ordering is the point: a test that has never passed against a vulnerable
implementation proves nothing about the control it claims to verify.

Convention for each module: a docstring that opens with the vulnerability in one
line, then the provenance block, then what was actually observed before the fix.

```python
"""<the vulnerability, in one line>.

PLAN.md step:      N
OWASP:             MCP07          <- or `Category:` where no OWASP id fits
Vulnerable commit: <sha>          <- the commit these exploits succeeded against
Findings:          THREAT_MODEL.md F-NN

<What was observed before the fix, concretely -- payloads and results. This is
the part that cannot be reconstructed later: once the code is fixed, nothing in
the repo records what the exploit actually did unless this docstring does.>
"""
```

Recording the observed behaviour matters more than the shas. When someone asks in
week six what a control actually prevented, "the test passes" is not an answer.

Mark tests with both `attack` and the relevant risk marker:

```python
@pytest.mark.attack
@pytest.mark.mcp07
def test_customer_cannot_read_another_customers_order(...): ...
```

Run the whole suite with `uv run pytest -m attack`.
