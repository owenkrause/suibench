# Source

Reproduces the Typus Finance permission-validation vulnerability documented by SlowMist:
https://slowmist.medium.com/is-the-move-language-secure-the-typus-permission-validation-vulnerability-755a5175f7c3

The vulnerable `update_v2` snippet is preserved from the legacy fixture. The surrounding
`Oracle`, `UpdateAuthority`, `version_check`, `update_`, and `init` scaffold is a minimal
reconstruction matching the public write-up's described shapes: a shared price oracle and a
shared authority set of permitted updater addresses.

The package is renamed to `challenge` for benchmark decontamination. The vulnerable entry point
does not contain comments naming the bug.

Confidence: high for the vulnerability and one-line authorization fix; the scaffold is
reconstructed rather than byte-for-byte original source.
