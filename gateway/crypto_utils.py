"""
Pure-Python RSA Cryptography Utility for DKIM Signing & Verification.
Compliant with RFC 3447 (PKCS #1 v2.2 / v1.5) and RFC 6376 (DKIM).
Requires zero external dependencies.
"""

import base64
import hashlib
import math
import re
import secrets
from typing import Dict, Optional, Tuple

# ASN.1 OID for rsaEncryption: 1.2.840.113549.1.1.1
OID_RSA_ENCRYPTION = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])

# DigestInfo prefix for SHA-256 (RFC 3447 Section 9.2, Note 1)
# SEQUENCE { SEQUENCE { OID sha256 (2.16.840.1.101.3.4.2.1), NULL }, OCTET STRING (32 bytes) }
SHA256_DIGEST_INFO_PREFIX = bytes([
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
])

# DigestInfo prefix for SHA-1 (legacy support)
SHA1_DIGEST_INFO_PREFIX = bytes([
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14
])

SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251
]


def _miller_rabin(n: int, k: int = 30) -> bool:
    """Miller-Rabin probabilistic primality test."""
    if n in (2, 3):
        return True
    if n < 2 or n % 2 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """Generates a cryptographic prime of the specified bit length."""
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if any(candidate % p == 0 for p in SMALL_PRIMES):
            continue
        if _miller_rabin(candidate):
            return candidate


# ---------------- ASN.1 DER Encoding / Decoding Helpers ----------------

def _der_len(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(len_bytes)]) + len_bytes


def _der_tag(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_integer(val: int) -> bytes:
    if val < 0:
        raise ValueError("Negative integers not supported")
    if val == 0:
        return _der_tag(0x02, b'\x00')
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'big')
    if val_bytes[0] & 0x80:
        val_bytes = b'\x00' + val_bytes
    return _der_tag(0x02, val_bytes)


def _der_sequence(*elements: bytes) -> bytes:
    return _der_tag(0x30, b''.join(elements))


def _der_bit_string(data: bytes) -> bytes:
    return _der_tag(0x03, b'\x00' + data)


def _der_null() -> bytes:
    return bytes([0x05, 0x00])


def _parse_der_length(der: bytes, offset: int) -> Tuple[int, int]:
    b = der[offset]
    offset += 1
    if b < 0x80:
        return b, offset
    num_bytes = b & 0x7F
    if num_bytes == 0 or offset + num_bytes > len(der):
        raise ValueError("Invalid DER length encoding")
    length = int.from_bytes(der[offset:offset + num_bytes], 'big')
    return length, offset + num_bytes


def _parse_der_element(der: bytes, offset: int) -> Tuple[int, bytes, int]:
    if offset >= len(der):
        raise ValueError("Unexpected end of DER stream")
    tag = der[offset]
    length, data_start = _parse_der_length(der, offset + 1)
    data_end = data_start + length
    if data_end > len(der):
        raise ValueError("DER element truncated")
    return tag, der[data_start:data_end], data_end


def _parse_der_integer(der: bytes, offset: int) -> Tuple[int, int]:
    tag, data, next_offset = _parse_der_element(der, offset)
    if tag != 0x02:
        raise ValueError(f"Expected DER INTEGER (0x02), got 0x{tag:02x}")
    return int.from_bytes(data, 'big'), next_offset


# ---------------- Key Representation & Formatting ----------------

class RSAKey:
    """Represents an RSA Keypair or Public Key."""

    def __init__(self, n: int, e: int, d: Optional[int] = None, p: Optional[int] = None, q: Optional[int] = None):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.bit_size = n.bit_length()
        self.byte_size = (self.bit_size + 7) // 8

    @property
    def is_private(self) -> bool:
        return self.d is not None

    def public_key(self) -> 'RSAKey':
        return RSAKey(self.n, self.e)

    def to_pkcs1_der_private(self) -> bytes:
        """Encodes private key to PKCS#1 RSAPrivateKey DER format."""
        if not self.is_private or not self.p or not self.q:
            raise ValueError("Full private key parameters required")
        dmp1 = self.d % (self.p - 1)
        dmq1 = self.d % (self.q - 1)
        iqmp = pow(self.q, -1, self.p)

        return _der_sequence(
            _der_integer(0),  # version
            _der_integer(self.n),
            _der_integer(self.e),
            _der_integer(self.d),
            _der_integer(self.p),
            _der_integer(self.q),
            _der_integer(dmp1),
            _der_integer(dmq1),
            _der_integer(iqmp),
        )

    def to_pkcs1_der_public(self) -> bytes:
        """Encodes public key to PKCS#1 RSAPublicKey DER format."""
        return _der_sequence(
            _der_integer(self.n),
            _der_integer(self.e),
        )

    def to_spki_der_public(self) -> bytes:
        """Encodes public key to X.509 SubjectPublicKeyInfo DER format."""
        algorithm_id = _der_sequence(
            bytes([0x06, len(OID_RSA_ENCRYPTION)]) + OID_RSA_ENCRYPTION,
            _der_null()
        )
        rsa_pub_bytes = self.to_pkcs1_der_public()
        return _der_sequence(
            algorithm_id,
            _der_bit_string(rsa_pub_bytes)
        )

    def to_private_pem(self) -> str:
        """Exports private key to standard PEM format."""
        der = self.to_pkcs1_der_private()
        b64 = base64.b64encode(der).decode('ascii')
        lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
        return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END RSA PRIVATE KEY-----\n"

    def to_public_pem(self) -> str:
        """Exports public key to standard SubjectPublicKeyInfo PEM format."""
        der = self.to_spki_der_public()
        b64 = base64.b64encode(der).decode('ascii')
        lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
        return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"

    def to_dkim_dns_value(self) -> str:
        """
        Formats public key for DKIM DNS TXT record.
        RFC 6376 Section 3.6.1: p= is base64 of public key.
        """
        der = self.to_spki_der_public()
        b64 = base64.b64encode(der).decode('ascii')
        return f"v=DKIM1; k=rsa; p={b64}"


def generate_rsa_key(bits: int = 2048) -> RSAKey:
    """Generates an RSA Key Pair (1024 or 2048 bits)."""
    if bits < 1024:
        raise ValueError("Key size must be at least 1024 bits")
    half_bits = bits // 2
    e = 65537
    while True:
        p = _generate_prime(half_bits)
        q = _generate_prime(bits - half_bits)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            d = pow(e, -1, phi)
            n = p * q
            return RSAKey(n, e, d, p, q)


def import_private_key_pem(pem_str: str) -> RSAKey:
    """Parses a PEM formatted RSA private key."""
    clean = re.sub(r'-----[^-]+-----', '', pem_str)
    der = base64.b64decode(clean.strip())
    # Parse PKCS#1 sequence
    tag, content, _ = _parse_der_element(der, 0)
    if tag != 0x30:
        raise ValueError("Expected SEQUENCE in private key DER")
    offset = 0
    version, offset = _parse_der_integer(content, offset)
    n, offset = _parse_der_integer(content, offset)
    e, offset = _parse_der_integer(content, offset)
    d, offset = _parse_der_integer(content, offset)
    p, offset = _parse_der_integer(content, offset)
    q, offset = _parse_der_integer(content, offset)
    return RSAKey(n, e, d, p, q)


def import_public_key_der_or_b64(key_data: str | bytes) -> RSAKey:
    """
    Parses a public key from base64 string (from DKIM DNS p= tag)
    or PEM string, accepting either SubjectPublicKeyInfo or PKCS#1 RSAPublicKey.
    """
    if isinstance(key_data, str):
        clean = re.sub(r'-----[^-]+-----', '', key_data)
        clean = re.sub(r'\s+', '', clean)
        der = base64.b64decode(clean)
    else:
        der = key_data

    tag, content, _ = _parse_der_element(der, 0)
    if tag != 0x30:
        raise ValueError("Expected SEQUENCE tag in DER")

    # Check if this is SubjectPublicKeyInfo (sequence with algorithm identifier)
    # If the first element is a SEQUENCE (0x30), it is SPKI.
    first_tag = content[0]
    if first_tag == 0x30:
        # SPKI format: SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
        _, alg_bytes, off = _parse_der_element(content, 0)
        bit_tag, bit_data, _ = _parse_der_element(content, off)
        if bit_tag != 0x03:
            raise ValueError("Expected BIT STRING in SPKI")
        # Strip unused bits counter byte (first byte of BIT STRING)
        rsa_pub_der = bit_data[1:]
        _, rsa_pub_content, _ = _parse_der_element(rsa_pub_der, 0)
        n, off2 = _parse_der_integer(rsa_pub_content, 0)
        e, _ = _parse_der_integer(rsa_pub_content, off2)
        return RSAKey(n, e)
    else:
        # PKCS#1 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
        n, off = _parse_der_integer(content, 0)
        e, _ = _parse_der_integer(content, off)
        return RSAKey(n, e)


# ---------------- RFC 3447 PKCS#1 v1.5 Signature & Verification ----------------

def rsa_sign_sha256(message_bytes: bytes, private_key: RSAKey) -> bytes:
    """
    Signs message bytes using RSA PKCS#1 v1.5 with SHA-256.
    Returns signature bytes of length equal to key byte length.
    """
    if not private_key.is_private:
        raise ValueError("Private key required for signing")

    h = hashlib.sha256(message_bytes).digest()
    digest_info = SHA256_DIGEST_INFO_PREFIX + h
    em_len = private_key.byte_size
    ps_len = em_len - len(digest_info) - 3

    if ps_len < 8:
        raise ValueError("Key size too small for SHA-256 signature")

    # EM = 0x00 || 0x01 || PS (0xFF) || 0x00 || DigestInfo
    em = b'\x00\x01' + (b'\xFF' * ps_len) + b'\x00' + digest_info
    m = int.from_bytes(em, 'big')
    s = pow(m, private_key.d, private_key.n)
    return s.to_bytes(em_len, 'big')


def rsa_verify_sha256(message_bytes: bytes, signature_bytes: bytes, public_key: RSAKey) -> bool:
    """
    Verifies RSA PKCS#1 v1.5 signature with SHA-256 against message bytes.
    """
    if len(signature_bytes) != public_key.byte_size:
        return False

    s = int.from_bytes(signature_bytes, 'big')
    if s >= public_key.n:
        return False

    m = pow(s, public_key.e, public_key.n)
    em = m.to_bytes(public_key.byte_size, 'big')

    # Expected EM format: 0x00 0x01 [0xFF]+ 0x00 [DigestInfo]
    if not em.startswith(b'\x00\x01'):
        return False

    # Find the separator 0x00 after the 0xFF padding
    sep_idx = em.find(b'\x00', 2)
    if sep_idx < 10:  # At least 8 bytes of 0xFF padding
        return False

    # Check padding bytes are all 0xFF
    if any(b != 0xFF for b in em[2:sep_idx]):
        return False

    digest_info = em[sep_idx + 1:]
    expected_hash = hashlib.sha256(message_bytes).digest()
    expected_digest_info = SHA256_DIGEST_INFO_PREFIX + expected_hash

    return digest_info == expected_digest_info
