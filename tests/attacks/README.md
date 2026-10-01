# Attack suite

One module per finding, named for its OWASP MCP Top 10 ID where it maps to one.

Each test here was written against **deliberately vulnerable code** and observed to
succeed at exploitation before the fix landed. After the fix it asserts the attack
fails. That ordering is the point: a test that has never passed against a vulnerable
implementation proves nothing about the control it claims to verify.

Convention for each module:

```python
# Vulnerable commit:  <sha>          <- the commit this exploit succeeded against
# Fix commit:         <sha>
# PLAN.md step:       N
# OWASP:              MCP07
```

Mark tests with both `attack` and the relevant risk marker:

```python
@pytest.mark.attack
@pytest.mark.mcp07
def test_customer_cannot_read_another_customers_order(...): ...
```

Run the whole suite with `uv run pytest -m attack`.
