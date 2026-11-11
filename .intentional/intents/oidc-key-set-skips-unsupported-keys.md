---
wyrwood: patch
---

Sign-in now works with an identity provider whose key set also holds an
elliptic-curve key on a curve Wyrwood cannot use, or an RSA key larger than it
accepts. Wyrwood ignores such a key and verifies with the other keys. Before,
the whole key set failed to load, and sign-in failed.
