"""
Schnorr Protocol 영지식 증명 - 난수(nonce) 재사용 시 개인키 탈취 증명
"""
import random

# ──────────────────────────────────────────────────────────────
# 유틸리티
# ──────────────────────────────────────────────────────────────
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def modinv(a, m):
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("모듈러 역원 없음")
    return x % m

def section(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


# ──────────────────────────────────────────────────────────────
# Schnorr 파라미터
#   p = 23  (소수),  q = 11  (부분군 위수, q | p-1),  g = 2
#
#   검증:  g^q mod p = 2^11 mod 23 = 2048 mod 23 = 1  (O)
#   부분군: {2,4,8,16,9,18,13,3,6,12,1}  (크기 11)
# ──────────────────────────────────────────────────────────────
p = 23          # 소수
q = 11          # 부분군 위수  (q | p-1 = 22)
g = 2           # 생성원 (order q)

assert pow(g, q, p) == 1

section("Schnorr Protocol 공개 파라미터")
print(f"\n  소수       p = {p}")
print(f"  부분군 위수 q = {q}   (q | p-1 = {p-1})")
print(f"  생성원      g = {g}")
print(f"\n  [검증] g^q mod p = {g}^{q} mod {p} = {pow(g,q,p)}  (반드시 1)")


# ──────────────────────────────────────────────────────────────
# 증명자(Prover) 키 설정
#   개인키 x,   공개키 y = g^x mod p
# ──────────────────────────────────────────────────────────────
x = random.randint(2, q - 1)          # 개인키 (비공개)
y = pow(g, x, p)                       # 공개키

section("증명자(Prover) 키")
print(f"\n  개인키  x = {x}          (비공개 — 증명자만 보유)")
print(f"  공개키  y = g^x mod p = {g}^{x} mod {p} = {y}   (공개)")


# ──────────────────────────────────────────────────────────────
# Schnorr 프로토콜 1회 정상 실행
#
#  1) 증명자: 난수 r 선택,  t = g^r mod p  전송 (commitment)
#  2) 검증자: 챌린지 c 전송
#  3) 증명자: s = (r + c*x) mod q  전송 (response)
#  4) 검증자: g^s mod p == t * y^c mod p  확인
# ──────────────────────────────────────────────────────────────
section("정상 실행 (1회) — 영지식 증명 확인")

r  = random.randint(1, q - 1)
t  = pow(g, r, p)
c  = random.randint(1, q - 1)
s  = (r + c * x) % q

lhs = pow(g, s, p)
rhs = (t * pow(y, c, p)) % p
ok  = (lhs == rhs)

print(f"""
  [Step 1] 증명자  난수 r = {r}  선택  →  t = g^r mod p = {t}  전송
  [Step 2] 검증자  챌린지 c = {c}  전송
  [Step 3] 증명자  s = (r + c*x) mod q = ({r} + {c}*{x}) mod {q} = {s}  전송
  [Step 4] 검증자  g^s mod p = {lhs}
           t * y^c mod p  = {t} * {y}^{c} mod {p} = {rhs}
  [결과]   검증 {'성공 (OK)' if ok else '실패'}
""")


# ──────────────────────────────────────────────────────────────
# 취약점 시뮬레이션: 증명자가 동일한 난수 r 을 두 번 사용
#
#  세션 1: t1 = g^r mod p,  챌린지 c1,  응답 s1 = (r + c1*x) mod q
#  세션 2: t2 = g^r mod p,  챌린지 c2,  응답 s2 = (r + c2*x) mod q
#
#  공격:
#    s1 - s2 ≡ (c1 - c2)*x  (mod q)
#    x ≡ (s1 - s2) * (c1 - c2)^{-1}  (mod q)
# ──────────────────────────────────────────────────────────────
section("취약점 공격 — 동일 난수 r 재사용 시 개인키 탈취")

# 두 세션에서 동일한 r (nonce) 재사용
r_reused = random.randint(1, q - 1)
t_reused = pow(g, r_reused, p)

# 세션 1
c1 = random.randint(1, q - 1)
s1 = (r_reused + c1 * x) % q

# 세션 2 — 다른 챌린지, 같은 r
c2 = random.randint(1, q - 1)
while c2 == c1:                        # 반드시 c1 != c2 이어야 공격 가능
    c2 = random.randint(1, q - 1)
s2 = (r_reused + c2 * x) % q

print(f"""
  [세션 1]
    증명자 전송  t  = g^r mod p = {g}^{r_reused} mod {p} = {t_reused}
    검증자 전송  c1 = {c1}
    증명자 전송  s1 = (r + c1*x) mod q = ({r_reused} + {c1}*{x}) mod {q} = {s1}

  [세션 2 — 동일 r 재사용]
    증명자 전송  t  = g^r mod p = {t_reused}   (세션 1과 동일!)
    검증자 전송  c2 = {c2}
    증명자 전송  s2 = (r + c2*x) mod q = ({r_reused} + {c2}*{x}) mod {q} = {s2}
""")

# ── 개인키 복구
print("  [공격 — 수학적 유도]")
print(f"    s1           = r + c1*x  (mod q)")
print(f"    s2           = r + c2*x  (mod q)")
print(f"    s1 - s2      = (c1 - c2)*x  (mod q)")
print(f"    {s1} - {s2}      = ({c1} - {c2})*x  (mod {q})")

diff_s = (s1 - s2) % q
diff_c = (c1 - c2) % q
inv_dc = modinv(diff_c, q)

x_cracked = (diff_s * inv_dc) % q

print(f"\n    x = (s1-s2) * modinv(c1-c2, q)  mod q")
print(f"      = {diff_s} * modinv({diff_c}, {q})  mod {q}")
print(f"      = {diff_s} * {inv_dc}  mod {q}")
print(f"      = {diff_s * inv_dc}  mod {q}")
print(f"      = {x_cracked}")

print(f"\n  [결과]")
print(f"    실제   개인키  x          = {x}")
print(f"    탈취된 개인키  x_cracked  = {x_cracked}")
print(f"    탈취 성공 여부: {x_cracked == x}")

# ── 탈취한 개인키로 공개키 재현
y_check = pow(g, x_cracked, p)
print(f"\n    공개키 재현 확인: g^x_cracked mod p = {g}^{x_cracked} mod {p} = {y_check}")
print(f"    실제 공개키 y                        = {y}")
print(f"    일치: {y_check == y}")


# ──────────────────────────────────────────────────────────────
# 핵심 요약
# ──────────────────────────────────────────────────────────────
section("핵심 요약")
print("""
  Schnorr Protocol 의 안전성 가정:
    - 난수 r 은 매 세션마다 반드시 새로 생성해야 함
    - t = g^r 이 동일하면 검증자(또는 도청자)가 두 응답 s1, s2 와
      두 챌린지 c1, c2 만으로 개인키 x 를 바로 계산 가능

  수식 정리:
    s1 = r + c1*x  (mod q)   ... (1)
    s2 = r + c2*x  (mod q)   ... (2)
    (1)-(2): s1-s2 = (c1-c2)*x  (mod q)
    => x = (s1-s2) * (c1-c2)^{-1}  (mod q)

  교훈:
    난수(nonce) 한 번 재사용 = 개인키 완전 노출
    => 서명/ZKP 구현 시 CSPRNG 로 매 세션 독립 난수 필수
""")
