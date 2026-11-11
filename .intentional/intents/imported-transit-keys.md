---
wyrwood: patch
wyrwood-docs: patch
---

**OpenBao keys** and the policy editor list Transit keys again after a key is imported into the Transit mount. OpenBao then lists an `import/` directory beside the keys, and the controller tried to read it as a key, so both pages showed no Transit key and said OpenBao did not answer. A key that cannot be read no longer empties the list: the page names that key and the failure, such as permission refused, and lists the others. "OpenBao did not answer" now shows only when OpenBao did not answer; a refused list says permission refused.
