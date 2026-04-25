"""
Diffie-Hellman 키합의 + AES 암호화/복호화 시뮬레이션
"""
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ──────────────────────────────────────────────
# 1. DH 공개 파라미터 (소수 p, 원시근 g)
# ──────────────────────────────────────────────
# 실습용 작은 소수. 실제 환경에서는 2048비트 이상 사용
p = 23   # 소수 (prime)
g = 5    # 원시근 (primitive root / generator)

print("=" * 55)
print("    Diffie-Hellman 키합의 + AES 암호화 시뮬레이션")
print("=" * 55)
print(f"\n[공개 파라미터]  p = {p},  g = {g}\n")


# ──────────────────────────────────────────────
# 2. 각자 비밀키 생성 (2 이상 p-2 이하)
# ──────────────────────────────────────────────
a = random.randint(2, p - 2)   # User A의 비밀키
b = random.randint(2, p - 2)   # User B의 비밀키

print(f"[User A] 비밀키 a = {a}  (비공개)")
print(f"[User B] 비밀키 b = {b}  (비공개)\n")


# ──────────────────────────────────────────────
# 3. 공개값 계산 및 교환
#    A = g^a mod p
#    B = g^b mod p
# ──────────────────────────────────────────────
A = pow(g, a, p)   # User A가 User B에게 전송
B = pow(g, b, p)   # User B가 User A에게 전송

print(f"[User A → User B] 공개값 A = g^a mod p = {g}^{a} mod {p} = {A}")
print(f"[User B → User A] 공개값 B = g^b mod p = {g}^{b} mod {p} = {B}\n")


# ──────────────────────────────────────────────
# 4. 공유 비밀키(shared secret) 계산
#    User A: S = B^a mod p
#    User B: S = A^b mod p
# ──────────────────────────────────────────────
S_a = pow(B, a, p)   # User A가 계산
S_b = pow(A, b, p)   # User B가 계산

print(f"[User A] 공유 비밀 S = B^a mod p = {B}^{a} mod {p} = {S_a}")
print(f"[User B] 공유 비밀 S = A^b mod p = {A}^{b} mod {p} = {S_b}")
assert S_a == S_b, "키합의 실패!"
print(f"\n[OK] 공유 비밀키 일치: S = {S_a}\n")


# ──────────────────────────────────────────────
# 5. 공유 비밀 → AES-128 키 유도 (SHA-256 해시)
# ──────────────────────────────────────────────
shared_bytes = S_a.to_bytes((S_a.bit_length() + 7) // 8, 'big')
aes_key = hashlib.sha256(shared_bytes).digest()[:16]   # 128비트 키

print(f"[키 유도] SHA-256({S_a}) 앞 16바이트 → AES 키")
print(f"          AES 키 = {aes_key.hex()}\n")


# ──────────────────────────────────────────────
# 6. User A가 메시지 암호화 (AES-CBC)
# ──────────────────────────────────────────────
message = "Hello, User B! This is a secret message."
print(f"[User A] 평문 메시지: \"{message}\"")

cipher_enc = AES.new(aes_key, AES.MODE_CBC)
iv         = cipher_enc.iv
ciphertext = cipher_enc.encrypt(pad(message.encode(), AES.block_size))

print(f"[User A → User B] IV         = {iv.hex()}")
print(f"[User A → User B] 암호문(hex) = {ciphertext.hex()}\n")


# ──────────────────────────────────────────────
# 7. User B가 암호문 복호화
# ──────────────────────────────────────────────
cipher_dec  = AES.new(aes_key, AES.MODE_CBC, iv=iv)
decrypted   = unpad(cipher_dec.decrypt(ciphertext), AES.block_size)
plaintext   = decrypted.decode()

print(f"[User B] 복호화된 메시지: \"{plaintext}\"")
print(f"\n{'=' * 55}")
print("  시뮬레이션 완료 — DH 키합의 및 암·복호화 성공!")
print("=" * 55)
