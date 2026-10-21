Perform a security audit of this repository. Analyze the code for vulnerabilities and security anti-patterns. 
Treat the following list as inclusive but not exhaustive and consider any other potential security issues that are not listed:

1. **Injection Flaws** — SQL injection, command injection, XSS, template injection, path traversal.
2. **Authentication & Authorization** — Are auth mechanisms sound? Any bypasses? Hardcoded credentials?
3. **Secrets Management** — Any API keys, tokens, or passwords in code or config files?
4. **Input Validation** — Is user input validated and sanitized at trust boundaries?
5. **Cryptography** — Are crypto primitives used correctly? Any weak algorithms or hardcoded keys?
6. **Dependencies** — Known CVEs in dependencies? Pinned versions?
7. **Configuration** — Debug mode enabled? Verbose error messages exposed? CORS misconfigured?

Rate overall risk (Low / Medium / High / Critical) and list findings with severity, affected files, and recommended fixes. 
Flag any issues that need immediate attention.

## sudoubt specifics

sudoubt runs as root through sudo and its caller is assumed to be hostile. README.md is the spec and the "Hard rules" in CLAUDE.md are the security model. Also check:

- Any way to act on a path outside `ALLOWED_ROOTS`: symlinks, `..`, races between check and use (TOCTOU), bind mounts, hard links.
- Any way to get root: setuid or setgid bits, chown to system accounts, xattrs other than the Ceph quota ones, ACLs that grant access outside the project.
- Any way around the rate limit or the file lock, or to break its state in `/run/sudoubt/`.
- Exit codes and error messages that do not match the README.
- Code that runs a shell or an external binary.

Do not change any files. Only report.
