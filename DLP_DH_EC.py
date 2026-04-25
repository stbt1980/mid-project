"""
DLP 기반 DH 와 EC 기반 DH 에서
generate_private_key() 로 생성된 키의 수학적 파라미터 시뮬레이션
"""
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.backends import default_backend


def section(title):
    print("\n" + "=" * 62)
    print(f"  {title}")
    print("=" * 62)

def show_num(label, value, width=55):
    hex_str = format(value, 'X')
    bit_len = value.bit_length()
    print(f"\n  [{label}]  ({bit_len} bits)")
    for i in range(0, len(hex_str), width):
        print(f"    {hex_str[i:i+width]}")


# ============================================================
# 1. DLP 기반 DH
# ============================================================
section("1. DLP 기반 DH  --  generate_private_key() 수학적 파라미터")

print("\n  [파라미터 생성]  generator=2, key_size=512 bits")

params      = dh.generate_parameters(generator=2, key_size=512,
                                     backend=default_backend())
param_nums  = params.parameter_numbers()
p = param_nums.p   # 소수 모듈러스
g = param_nums.g   # 생성원 (generator)

print(f"\n  공개 파라미터 (양측 공유)")
show_num("소수 p", p)
print(f"\n  생성원 g = {g}")

# -- 개인키 생성
priv_key_dlp = params.generate_private_key()
priv_nums    = priv_key_dlp.private_numbers()
x            = priv_nums.x        # 개인키 값 (비밀 지수)

# -- 공개키 유도
pub_nums = priv_key_dlp.public_key().public_numbers()
y        = pub_nums.y             # 공개키 값  y = g^x mod p

print(f"\n  --- generate_private_key() 결과 ---")
show_num("개인키  x  (비밀 지수)", x)
show_num("공개키  y = g^x mod p", y)

# -- 수학적 검증
verified = (y == pow(g, x, p))
print(f"\n  [검증]  pow(g, x, p) == y  -->  {verified}")


# ============================================================
# 2. EC 기반 DH  --  SECP256R1 (NIST P-256)
# ============================================================
section("2. EC 기반 DH  --  generate_private_key() 수학적 파라미터")

# SECP256R1 (P-256) 곡선 파라미터 (RFC 5480 / NIST FIPS 186-4)
p_ec = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a_ec = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b_ec = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
Gx   = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy   = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
n_ec = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
h_ec = 1

print(f"\n  곡선: SECP256R1 (NIST P-256)  --  공개 파라미터")
print(f"\n  곡선 방정식: y^2 = x^3 + ax + b  (mod p)")
show_num("p  (소수 체 모듈러스)", p_ec)
show_num("a  (곡선 계수 a)",      a_ec)
show_num("b  (곡선 계수 b)",      b_ec)
show_num("Gx (기저점 x 좌표)",    Gx)
show_num("Gy (기저점 y 좌표)",    Gy)
show_num("n  (군의 위수 order)",  n_ec)
print(f"\n  h  (코팩터) = {h_ec}")

# -- 개인키 생성
priv_key_ec  = ec.generate_private_key(ec.SECP256R1(), default_backend())
priv_ec_nums = priv_key_ec.private_numbers()
d            = priv_ec_nums.private_value    # 개인키 스칼라 d

# -- 공개키 유도  Q = d * G (타원 곡선 스칼라 곱)
pub_ec_nums = priv_key_ec.public_key().public_numbers()
Qx = pub_ec_nums.x   # 공개키 점 Q의 x 좌표
Qy = pub_ec_nums.y   # 공개키 점 Q의 y 좌표

print(f"\n  --- generate_private_key() 결과 ---")
show_num("개인키  d  (스칼라)", d)
print(f"\n  공개키 점  Q = d * G  (타원 곡선 스칼라 곱)")
show_num("Qx (공개키 점 x 좌표)", Qx)
show_num("Qy (공개키 점 y 좌표)", Qy)

# -- 공개키가 곡선 위의 점인지 검증  Qy^2 mod p == (Qx^3 + a*Qx + b) mod p
lhs  = pow(Qy, 2, p_ec)
rhs  = (pow(Qx, 3, p_ec) + a_ec * Qx + b_ec) % p_ec
print(f"\n  [검증]  Qy^2 mod p == Qx^3 + a*Qx + b mod p  -->  {lhs == rhs}")


# ============================================================
# 3. 두 방식 비교 요약
# ============================================================
section("3. DLP-DH vs EC-DH  비교 요약")
print("""
  구분           DLP 기반 DH (고전)         EC 기반 DH (타원곡선)
  -----------    -----------------------    -------------------------
  수학 구조      유한체 곱셈군               타원 곡선 점 덧셈군
  어려운 문제    이산 로그 문제 (DLP)         타원곡선 이산 로그 (ECDLP)
  개인키         정수 x  (비밀 지수)          정수 d  (스칼라)
  공개키         y = g^x mod p              점 Q = d * G
  키 크기        512 ~ 4096 bits            224 ~ 521 bits (더 짧음)
  안전성 근거    큰 p 에서 DLP 풀기 어려움   큰 n 에서 ECDLP 풀기 어려움
""")
