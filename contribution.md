# Contributing to PasteGuard

Thank you for your interest in making the clipboard safer for everyone!  
We welcome bug reports, feature requests, documentation fixes, and code contributions.

---

## Code of Conduct

Be respectful, constructive, and assume good faith. Harassment of any kind won't be tolerated.

---

## How to Contribute

1. **Fork** the repository and create your branch from `main`.
2. **Make your changes** – keep them focused and clearly described.
3. **Test** your changes thoroughly. If you add new detection patterns, run the test suite:

   ```bash
   python -m pytest tests/
   ```

4. **Commit** with a clear message (e.g., `Add detection for certutil download`).
5. **Push** to your fork and open a Pull Request.
6. In your PR, explain what you changed and why.

---

## Reporting Bugs

If you find a security bypass, please do **not** open a public issue.  
Instead, email the maintainer directly (see the repository's security policy).

For non‑security bugs, open a GitHub Issue with:

- PasteGuard version and OS
- Exact command that wasn't detected
- Expected vs. actual behavior

---

## Feature Requests

We love ideas! Open an Issue with the tag `enhancement` and describe the **problem you want solved**, not just the solution.

---

## Code Style

- Follow PEP 8.
- Keep functions small and well‑documented.
- If you add a new malicious pattern, add a comment explaining the real‑world attack it catches.
