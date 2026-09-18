---
type: regex
pattern: 'localStorage\.(set|get)Item\s*\(\s*[''"`][^''"`]*(token|session|auth|user)'
flags: i
match: not_contains
target: trace
arm: both
---
