-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: openssl
Binary: openssl, libssl1.1, libcrypto1.1-udeb, libssl1.1-udeb, libssl-dev, libssl-doc
Architecture: any all
Version: 1.1.1k-1+deb11u2
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@lists.alioth.debian.org>
Uploaders: Christoph Martin <christoph.martin@uni-mainz.de>, Kurt Roeckx <kurt@roeckx.be>, Sebastian Andrzej Siewior <sebastian@breakpoint.cc>
Homepage: https://www.openssl.org/
Standards-Version: 4.5.0
Vcs-Browser: https://salsa.debian.org/debian/openssl
Vcs-Git: https://salsa.debian.org/debian/openssl.git
Testsuite: autopkgtest
Testsuite-Triggers: perl
Build-Depends: debhelper-compat (= 12), m4, bc, dpkg-dev (>= 1.15.7)
Package-List:
 libcrypto1.1-udeb udeb debian-installer optional arch=any
 libssl-dev deb libdevel optional arch=any
 libssl-doc deb doc optional arch=all
 libssl1.1 deb libs optional arch=any
 libssl1.1-udeb udeb debian-installer optional arch=any
 openssl deb utils optional arch=any
Checksums-Sha1:
 bad9dc4ae6dcc1855085463099b5dacb0ec6130b 9823400 openssl_1.1.1k.orig.tar.gz
 60ec762123a6eeee4136942d50f67369de960a9d 488 openssl_1.1.1k.orig.tar.gz.asc
 a795f44a2f0b1f93bcc5f973227f94d76fc1d6f0 98172 openssl_1.1.1k-1+deb11u2.debian.tar.xz
Checksums-Sha256:
 892a0875b9872acd04a9fde79b1f943075d5ea162415de3047c327df33fbaee5 9823400 openssl_1.1.1k.orig.tar.gz
 addeaa197444a62c6063d7f819512c2c22b42141dec9d8ec3bff7e4518e1d1c9 488 openssl_1.1.1k.orig.tar.gz.asc
 43d986c7cb4e48bbe094d185a58c8fc4de54253cf2783f03fa3c4676cab98926 98172 openssl_1.1.1k-1+deb11u2.debian.tar.xz
Files:
 c4e7d95f782b08116afa27b30393dd27 9823400 openssl_1.1.1k.orig.tar.gz
 8119ccb30bf6a12176a320041d225406 488 openssl_1.1.1k.orig.tar.gz.asc
 f9dc94170286d0d0c2355993e5f2e78d 98172 openssl_1.1.1k-1+deb11u2.debian.tar.xz

-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEZCVGlf/wqkRmzBnme5boFiqM9dEFAmIvpncACgkQe5boFiqM
9dGpuxAAh0+/qK/1+7R232kINFR0r+ZLMRy/eaYzCIu20OKRy5KzKDcOnIAQKJWF
TXgVsLDSP9ztDQCFZ2gomiRt8LY87d+BG6wMTaabovecECWZPuJTZ3nNhsFT40d7
MdxBoI4NgsRts2FYNG4homl6Dk+6aRleWtPRANlfcAeakmAuBLLrwWIlB2TwG+E0
/1tHk34iXJCBFNNeZW/uFvkGGPr3CqFQAzJMMqumldTigUpoNQ95nfrvOTlHdZMT
pf+dP3GGZYM+vfTuMsZwKWPHlWjzZdGZL2RyHGpuHrmCzzhSqeiBY84gHnghXOMz
4njX0uNslgefm8pH20ekhGSDkM10gvapWlEeJSnKzt3zKzWQDiASc/AxnC+kTEDX
UFfrGyt7mO0mG8WcKR/A1fewG6yUkAoySb6i+kyZfhM8jIW/jb57Sij5lhpEwMgG
Mnu418MSzf1F7gtnoOTv7F3vk78Q/5JWtVQBVJ1crLMdIp+ozc64iVWJkBBkrhlk
onw7COR6Y9ETr7Mt3bD+gxZ0YrqXQqUbeRCUocQiYZjYaPIB1VhAtpm260Kh88LY
7tn7DAKs2J3PHUwTYtEUEO5XUObQbAOae00p30RYmAarLTuNVWrqhGDXpkXoyEPl
ls/yF2O6rXAaA3nlgisrvKyTlUwETee7cVYLuzNE5X28XmFd+O8=
=sL53
-----END PGP SIGNATURE-----
