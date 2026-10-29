# AI usage: dsc26-cyb-w03

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

Claude (Anthropic) helped draft validation.py, policy.py, passwords.py and tests/test_edge_cases.py.
I read the code and ran the tests myself.

## What AI got wrong

The AI's draft passed the public tests and my edge-case tests on the first run, so I did not find a
behaviour bug in the final code. The one thing I caught on review was a leftover no-op expression
(`make(1, 8, 5) if False else ...`) in my own test list, which I removed. The risky spots the task
warns about (`\d` accepting Unicode digits, `int()` accepting Unicode digits in the stored hash,
and a stored hash choosing how many bytes get compared) are covered by explicit tests, so I checked
them by running those tests rather than trusting the draft.

## In my own words

1. `get_document` returns 404, not 403, because a 403 confirms that the other client's contract
   exists, which leaks information and lets someone enumerate document ids. A 404 looks the same as
   a document that was never there.

2. If the verifier compared only as many bytes as the stored hash contains, a truncated hash would
   need just a short prefix to match, which is far easier to guess and would accept wrong passwords.
   Requiring exactly 32 bytes means the stored value cannot weaken the comparison.

1. Why does `get_document` return 404 rather than 403 when a client asks for another client's contract?

2. Why must `verify_password` refuse a stored hash that is shorter than 32 bytes, even though the prefix matches?
