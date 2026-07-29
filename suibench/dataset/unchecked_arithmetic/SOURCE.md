# Source

Authored for this repo as an intentionally-vulnerable test contract.

Vuln: integer-division truncation in `deposit` share accounting enables a
donation / share-inflation attack (the classic first-depositor / donation bug).
