-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: openssl
Binary: openssl, libssl1.1, libcrypto1.1-udeb, libssl1.1-udeb, libssl-dev, libssl-doc
Architecture: any all
Version: 1.1.1k-1+deb11u1
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
 467279984d18bb00f23c016129026e790bab1e99 94244 openssl_1.1.1k-1+deb11u1.debian.tar.xz
Checksums-Sha256:
 892a0875b9872acd04a9fde79b1f943075d5ea162415de3047c327df33fbaee5 9823400 openssl_1.1.1k.orig.tar.gz
 addeaa197444a62c6063d7f819512c2c22b42141dec9d8ec3bff7e4518e1d1c9 488 openssl_1.1.1k.orig.tar.gz.asc
 68e00f47162ecea0273b4ba453503307b8430bb2d163f92cbbec6f51b11061fd 94244 openssl_1.1.1k-1+deb11u1.debian.tar.xz
Files:
 c4e7d95f782b08116afa27b30393dd27 9823400 openssl_1.1.1k.orig.tar.gz
 8119ccb30bf6a12176a320041d225406 488 openssl_1.1.1k.orig.tar.gz.asc
 1cbf2b5e8311fce17ff34c2a4c7a833a 94244 openssl_1.1.1k-1+deb11u1.debian.tar.xz

-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEZCVGlf/wqkRmzBnme5boFiqM9dEFAmEkwSgACgkQe5boFiqM
9dGZTw//W0Kryucaj1hTkhI4JH9zMzz5G0GW8h0sqHnB/GvhdHAcWfEKUZ+OUSKj
jT5YMgKzVMtnVkWPofAqUaEd3iUZV10nK+WZ2oI7iysabqcpcXM3nqqMBeFPcT7f
q5VAMZRTvMcQCSuEr3JNtgCzF3dIESYPzL6xML0VESh8Q6doPaZ4e3EumLW4yPkX
8zhwEkrnoeFQZUqbHdoRXujb3fo2fOzVKpCszWWCJpmlSBz/WQLZzNsPkZ2C1Gty
KrvyGbRUG1OQmm4GMScVkGXJRBWdIxFoedm4f/AdlgSjDUlYeRdxgMho2Gs8Vx3k
Lr/CiHIu94seM9FWp350EWw4GGq7xG9tBmeEJd2Ww+9lErXjkk5lSJ98iVXMGaLx
V2pX2XALQUI24wWDrKus9sk7tmXb4WZ+kiTXlT4HHHD4i2I6tGomjCXM+6+c0Mcj
st4bH/vEPikaKKGzISBVZigCV2p/xv20IXupIrUwVA0CnfTeE/y/zyoKX2+yDo3y
YfjIpmeo5kNE/l1grISkamfHocfkddbqqKdzYKBKayCibKLzed526wkCYXiEiCgj
orq7yVy/Gk15lFiEB8o7Q4cnacRzIPmipegOe+ySupn2JepW1Tm+K/VlYEYhhf7a
EAQrO6bVLYaw6FfWrpq+n43T0zMvjK8dGcA0qxP7LUZpFTZnVcA=
=6iya
-----END PGP SIGNATURE-----
