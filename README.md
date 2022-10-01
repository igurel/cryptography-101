## Books
* [Applied Cryptography](https://www.schneier.com/books/applied-cryptography/) (Bruce Schneier)
* [Introduction to Modern Cryptography: Principles and Protocols](https://www.amazon.com/Introduction-Modern-Cryptography-Principles-Protocols/dp/1584885513) (Jonathan Katz & Yehuda Lindell)
* [Real-World Cryptography](https://www.manning.com/books/real-world-cryptography) (David Wong)
* [The Joy of Cryptography](https://joyofcryptography.com/) (Mike Rosulek)

## Courses
* [Cryptography I | Stanford Online](https://online.stanford.edu/courses/soe-y0001-cryptography-i)
* [Cryptography II | Stanford Online](https://online.stanford.edu/courses/soe-y0002-cryptography-ii)

## Crypto Attacks and Vulnerabilities
#### AES
* [Cache-timing attacks on AES](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf) - Daniel J. Bernstein
* [Cryptanalysis of OCB2: Attacks on Authenticity and Confidentiality](https://eprint.iacr.org/2019/311.pdf)
* [Padding Oracle Attack on CBC](https://en.wikipedia.org/wiki/Padding_oracle_attack)
#### Digest
* [MD5 Nostradamus Attack](https://www.win.tue.nl/hashclash/Nostradamus/)
* [SHA-1 collision attacks](https://rwc.iacr.org/2018/Slides/Karpman.pdf)
#### ECC
* [Practical Invalid Curve Attacks on TLS-ECDH](https://owasp.org/www-pdf-archive/Practical_Invalid_Curve_Attacks_on_TLS-ECDH_-_Juraj_Somorovsky.pdf)
* [Side channel attacks on implementations of Curve25519](https://eprint.iacr.org/2017/806.pdf)
* [Lattice-based weak curve fault attack on ECDSA](https://eprint.iacr.org/2021/129.pdf)
* [Lattice Attacks against Weak ECDSA Signatures](https://eprint.iacr.org/2019/023.pdf)
* [CVE-2022-21449: Psychic Signatures in Java – Neil Madden](https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/)
#### Format Preserving Encryption
* [Breaking The FF3 Format Preserving Encryption](https://rwc.iacr.org/2018/Slides/Durak.pdf)
#### PQC
* [Attacks on NIST PQC 3rd Round Candidates](https://iacr.org/submit/files/slides/2021/rwc/rwc2021/22/slides.pdf)
#### RSA
* [Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1 v1.5](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf) - Daniel Bleichenbacher
* [New Attacks on PKCS#1 v1.5 Encryption](https://www.iacr.org/archive/eurocrypt2000/1807/18070374-new.pdf)
* [Coppersmith's attack & RSA](https://en.wikipedia.org/wiki/Coppersmith%27s_attack)
* [Lattice attacks on RSA](https://www.cis.upenn.edu/~cis556/lattices.pdf) - Nadia Heninger
#### Others
* [Cache Attacks on the Cloud](https://rwc.iacr.org/2016/Slides/RWCCloudCacheAttacksFinal.pdf)
* [Practical attacks on real world crypto implementations](https://rwc.iacr.org/2016/Slides/somorosky-2016-01-RWC.pdf)
* [Cache Attacks on the Cloud](https://rwc.iacr.org/2016/Slides/RWCCloudCacheAttacksFinal.pdf)
* [The 9 Lives of Bleichenbacher's CAT: New Cache ATtacks on TLS Implementations](https://rwc.iacr.org/2020/slides/Ronen.pdf)
* [TPM-Fail: TPM meets Timing and Lattice Attacks](https://rwc.iacr.org/2020/slides/Moghimi.pdf)

## Full Homomorphic Encryption
* [Introduction to FHE by Pascal Paillier](https://fhe.org/talks/introduction-to-fhe-by-pascal-paillier)
* [https://fhe.org/resources](https://fhe.org/resources)
* [GitHub - zama-ai/concrete: Concrete ecosystem is a set of crates that implements Zama's variant of TFHE](https://github.com/zama-ai/concrete)
* [GitHub - microsoft/SEAL: Microsoft SEAL is an easy-to-use and powerful homomorphic encryption library](https://github.com/microsoft/SEAL)
* [GitHub - homenc/HElib: HElib is an open-source software library that implements homomorphic encryption](https://github.com/HomEnc/HElib)
* [PALISADE Homomorphic Encryption Software Library (palisade-crypto.org)](https://palisade-crypto.org/software-library/)

## Post Quantum Cryptography
* [Post-Quantum Cryptography | CSRC (nist.gov)](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post-Quantum-Cryptography-Standardization)
* [NISTIR 8413, PQC Project Third Round Report | CSRC](https://csrc.nist.gov/publications/detail/nistir/8413/final)
* [The Beginning of the End: The First NIST PQC Standards](https://csrc.nist.gov/csrc/media/Presentations/2022/the-beginning-of-the-end-the-first-nist-pqc-standa/images-media/pkc2022-march2022-moody.pdf)
* [CRYSTALS (Cryptographic Suite for Algebraic Lattices)  Kyber and Dilithium](https://pq-crystals.org/index.shtml)

# The Protocols
## TLS
### TLS RFCs
* [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)
* [RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2](https://www.rfc-editor.org/rfc/rfc5246)
* [RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc9147)
* [RFC 6347: The Datagram Transport Layer Security (DTLS) Protocol Version 1.2](https://www.rfc-editor.org/rfc/rfc9147)
### TLS Best Security Practices
* [RFC 7457: Summarizing Known Attacks on Transport Layer Security (TLS) and Datagram TLS (DTLS)](https://www.rfc-editor.org/rfc/rfc7457)
* [RFC 7525: Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)](https://www.rfc-editor.org/rfc/rfc7525)
* [RFC 7540: Hypertext Transfer Protocol Version 2 (HTTP/2)](https://www.rfc-editor.org/rfc/rfc7540) (Appendix A 'Cipher Suite Blacklist'’)
* [RFC 7925: Transport Layer Security (TLS)/Datagram Transport Layer Security (DTLS) Profiles for the Internet of Things](https://www.rfc-editor.org/rfc/rfc7925)
* [The Netherlands NCSC IT Security Guidelines for TLS](https://english.ncsc.nl/publications/publications/2021/january/19/it-security-guidelines-for-transport-layer-security-2.1)
* [BSI TR-02102-2: Use of Transport Layer security](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf)
* [NIST SP 800-52 Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
* [Eliminating Obsolete Transport Layer Security (TLS) by NSA](https://media.defense.gov/2021/Jan/05/2002560140/-1/-1/0/ELIMINATING_OBSOLETE_TLS_UOO197443-20.PDF)

### TLS Vulnerabilities
* [BEAST (TLS 1.0 and the use of AES CBC with predictable IV)](https://en.wikipedia.org/wiki/Transport_Layer_Security)
* [CRIME, TIME and BREACH (compression attacks))](https://en.wikipedia.org/wiki/CRIME)
* [Lucky 13](https://en.wikipedia.org/wiki/Lucky_Thirteen_attack)
* [POODLE (SSLv3 padding oracle attack)](https://en.wikipedia.org/wiki/POODLE)
* [SMACK (state machine attack)](https://mitls.org/pages/attacks/SMACK)
* [Logjam (weak DH groups)](https://en.wikipedia.org/wiki/Logjam_(computer_security))
* [SLOTH (Security Losses from Obsolete and Truncated Transcript Hashes CVE-2015-7575)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7575)
* [DROWN (breaking TLS with SSL 2.0)](https://drownattack.com/)
* [FREAK (factoring RSA export keys)](https://en.wikipedia.org/wiki/FREAK)
* [SWEET32 (birthday attacks on 64-bit block ciphers in CBC mode e.g. 3DES)](https://sweet32.info/)
* [SELFIE (affects TLS 1.3 with PSK mode)](https://eprint.iacr.org/2019/347.pdf)
* [Racoon Attack (affects TLS 1.2 and below when using DH)](https://raccoon-attack.com/)
## The Signal Protocol
* [A Formal Security Analysis of the Signal Messaging Protocol](https://eprint.iacr.org/2016/1013.pdf)
## WireGuard
* [WireGuard VPN](https://www.wireguard.com/)
# The Frameworks
* [The Noise Protocol Framework](http://www.noiseprotocol.org/)
# The NIST Publications
* [NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation: Methods and Techniques](https://csrc.nist.gov/publications/detail/sp/800-38a/final)
* [NIST SP 800-38B: Recommendation for Block Cipher Modes of Operation: the CMAC Mode for Authentication](https://csrc.nist.gov/publications/detail/sp/800-38b/final)
* [NIST SP 800-38C: Recommendation for Block Cipher Modes of Operation: the CCM Mode for Authentication and Confidentiality](https://csrc.nist.gov/publications/detail/sp/800-38c/final)
* [NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
* [NIST SP 800-38E: Recommendation for Block Cipher Modes of Operation: the XTS-AES Mode for Confidentiality on Storage Devices](https://csrc.nist.gov/publications/detail/sp/800-38e/final)
* [NIST SP 800-38F: Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping](https://csrc.nist.gov/publications/detail/sp/800-38f/final)
* [NIST SP 800-56A Rev.3: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final)
* [NIST SP 800-56B Rev. 2: Recommendation for Pair-Wise Key-Establishment Using Integer Factorization Cryptography](https://csrc.nist.gov/publications/detail/sp/800-56b/rev-2/final)
* [NIST SP 800-57 Part 1: Recommendation for Key Management: Part 1 – General](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
* [NIST SP 800-57 Part 2: Recommendation for Key Management: Part 2 – Best Practices for Key Management Organizations](https://csrc.nist.gov/publications/detail/sp/800-57-part-2/rev-1/final)
* [NIST SP 800-57 Part 3: Recommendation for Key Management, Part 3: Application-Specific Key Management Guidance](https://csrc.nist.gov/publications/detail/sp/800-57-part-3/rev-1/final)
* [NIST SP 800-130: A Framework for Designing Cryptographic Key Management Systems](https://csrc.nist.gov/publications/detail/sp/800-130/final)
* [SP 800-135 Rev. 1: RRecommendation for Existing Application-Specific Key Derivation Functions](https://csrc.nist.gov/publications/detail/sp/800-135/rev-1/final)
* [FIPS 186-4: Signature Standard (DSS)](https://csrc.nist.gov/publications/detail/fips/186/4/final)
* [FIPS 186-5 (Draft): Signature Standard (DSS)](https://csrc.nist.gov/publications/detail/fips/186/5/draft)










