---
wyrwood: patch
wyrwood-docs: patch
---

The controller image now builds. 0.6.0 has no controller image, because the image build did not copy the public `operator` package. Its archives, DEB and RPM packages, and Go module are not affected. To run the controller from the image, use this version.
