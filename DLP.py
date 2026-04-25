"""
이산 로그 문제 (DLP) -- 소수 p 비트수 증가에 따른 비밀키 탈취 시간 분석
알고리즘: Baby-Step Giant-Step (BSGS)   시간 복잡도: O(sqrt(p))
"""
import random, time, math


# ──────────────────────────────────────────────
# Miller-Rabin 소수 판정 (확률적)
# ──────────────────────────────────────────────
def is_prime(n, k=20):
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1; d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True


# ──────────────────────────────────────────────
# 정확히 bits 비트인 소수 생성
# ──────────────────────────────────────────────
def gen_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1   # MSB=1, LSB=1(홀수) 보장
        if is_prime(n):
            return n


# ──────────────────────────────────────────────
# Baby-Step Giant-Step 알고리즘
#
#  문제: g^x ≡ y (mod p)  에서 x 를 구한다
#
#  풀이:
#    m = ceil(sqrt(p-1))  으로 설정
#    x = i*m + j  (0 <= j < m, 0 <= i <= m) 로 표현하면
#
#    g^x = y
#    g^(im+j) = y
#    g^j = y * g^(-im)  =  y * (g^(-m))^i
#
#    Baby step: B[g^j mod p] = j  저장  (j=0..m-1)
#    Giant step: 값 y*(g^(-m))^i 를 B 에서 검색
#    일치 시: x = i*m + j
#
#  메모리/시간 제한:
#    effective_m = min(m, mem_limit) 로 단계 크기 조정
#    Giant step 횟수 = ceil((p-1)/effective_m) + 1
# ──────────────────────────────────────────────
def bsgs(g, y, p, time_limit=30.0, mem_limit=5_000_000):
    """
    Returns (x_found, elapsed_sec, status)
    status: 'SOLVED' | 'TIMEOUT' | 'NOT_FOUND'
    """
    n = p - 1                                    # 군의 위수
    m = int(math.isqrt(n)) + 1                  # 이론적 최적 단계 크기
    effective_m = min(m, mem_limit)              # 메모리 상한 적용
    t0 = time.perf_counter()

    # ── 아기발걸음 (Baby Step): g^j mod p 를 테이블에 저장
    baby = {}
    gj = 1
    for j in range(effective_m):
        baby[gj] = j
        gj = gj * g % p
        if j % 500_000 == 0 and j > 0:
            if time.perf_counter() - t0 > time_limit:
                return None, time.perf_counter() - t0, 'TIMEOUT'

    # g^(-effective_m) mod p  계산
    gm_inv = pow(pow(g, effective_m, p), -1, p)

    # ── 거인발걸음 (Giant Step): y * (g^(-effective_m))^i 를 테이블에서 검색
    max_giant = math.ceil(n / effective_m) + 1
    yi = y
    for i in range(max_giant):
        if yi in baby:
            x = (i * effective_m + baby[yi]) % n
            return x, time.perf_counter() - t0, 'SOLVED'
        yi = yi * gm_inv % p
        if i % 500_000 == 0 and i > 0:
            if time.perf_counter() - t0 > time_limit:
                return None, time.perf_counter() - t0, 'TIMEOUT'

    return None, time.perf_counter() - t0, 'NOT_FOUND'


# ══════════════════════════════════════════════════════════════
# 메인 시뮬레이션
# ══════════════════════════════════════════════════════════════
TIME_LIMIT = 30                                  # 케이스당 제한 시간 (초)
bit_sizes  = [8, 12, 16, 20, 24, 28, 32,
              36, 40, 44, 48, 52, 56, 60, 64]

print("=" * 78)
print("  이산 로그 문제 -- 비트수별 DLP 풀이 시간 측정  (BSGS, O(sqrt(p)))")
print("=" * 78)
print(f"\n  생성원 g = 2  고정,  각 케이스 제한 시간 = {TIME_LIMIT} 초\n")
print(f"  {'비트':>5}  {'BSGS 이론 스텝':>16}  {'소수 p':>22}  {'소요시간':>14}  상태")
print("  " + "-" * 74)

solved_pts = []     # (bits, elapsed) -- 외삽에 사용

for bits in bit_sizes:
    p      = gen_prime(bits)
    g      = 2
    x_real = random.randint(2, p - 2)
    y      = pow(g, x_real, p)

    steps_theory = 2 * (int(math.isqrt(p - 1)) + 1)   # 이론 스텝 수

    x_found, elapsed, status = bsgs(g, y, p, time_limit=TIME_LIMIT)

    if status == 'SOLVED':
        ok   = (pow(g, x_found, p) == y)
        flag = "해독 성공" if ok else "검증 오류"
        solved_pts.append((bits, max(elapsed, 1e-9)))
        print(f"  {bits:>5}  {steps_theory:>16,}  {p:>22}  {elapsed:>12.6f} s  {flag}")
    else:
        print(f"  {bits:>5}  {steps_theory:>16,}  {p:>22}  {'>' + str(TIME_LIMIT) + ' s':>14}  시간초과 -- 이후 외삽")
        break


# ──────────────────────────────────────────────
# 외삽 분석
#
#  BSGS 시간: T = C * sqrt(p) = C * 2^(bits/2)
#  양변에 log2 적용:
#    log2(T) = (bits/2) * log2(2) + log2(C)
#            = 0.5 * bits + log2(C)
#  -> log2(T) 는 bits 의 선형 함수 (기울기 ≈ 0.5)
#
#  측정 데이터로 선형 회귀 후 T=3600 (1시간) 인 bits 계산
# ──────────────────────────────────────────────
print()
print("=" * 78)
print("  외삽 분석   T = C * 2^(bits/2)  =>  log2(T) = 0.5 * bits + C")
print("=" * 78)

if len(solved_pts) < 2:
    print("\n  [오류] 외삽을 위한 데이터 포인트 부족")
else:
    # 최소제곱 선형 회귀: log2(T) = slope * bits + intercept
    pts   = solved_pts[-min(8, len(solved_pts)):]   # 최근 8개 사용
    n_pts = len(pts)
    sx    = sum(b for b, _ in pts)
    sy    = sum(math.log2(t) for _, t in pts)
    sxy   = sum(b * math.log2(t) for b, t in pts)
    sxx   = sum(b * b for b, _ in pts)
    denom = n_pts * sxx - sx ** 2

    slope = (n_pts * sxy - sx * sy) / denom
    inter = (sy - slope * sx) / n_pts

    print(f"\n  실측 회귀식: log2(T) = {slope:.4f} x bits + ({inter:.4f})")
    print(f"  이론 기울기 = 0.5000  |  실측 기울기 = {slope:.4f}\n")

    # 각 시간 목표에 대한 예상 비트수
    print(f"  {'목표 시간':>14}  {'예상 해독 가능 비트수':>22}  {'예상 소수 크기':>18}")
    print("  " + "-" * 58)
    targets = [
        (1,        "1 초"),
        (60,       "1 분"),
        (600,      "10 분"),
        (3_600,    "1 시간"),
        (86_400,   "1 일"),
        (2_592_000,"30 일"),
    ]
    for sec, label in targets:
        est_bits = (math.log2(sec) - inter) / slope
        print(f"  {label:>14}  {est_bits:>20.1f} bits  "
              f"  (p ~ 2^{est_bits:.0f})")

    bits_1h = (math.log2(3_600) - inter) / slope

    print(f"""
  ================================================================
  [결론]
  1시간(3600 초) 이내 BSGS 로 해독 가능한 최대 소수 비트수

      p 의 비트수  <  {bits_1h:.1f}  bits

  즉, p < 2^{int(bits_1h)+1} 수준의 DLP 는 현재 PC 에서
  1시간 안에 비밀키를 탈취할 수 있다.

  ================================================================
  [실제 권장 키 크기 -- NIST SP 800-131A Rev 2]
    DH / DSA / RSA  최소 권장: 2048 bits
    DH / DSA / RSA  강력 권장: 3072 bits
    EC 기반 (ECDH)  최소 권장: 256 bits

  1시간 한계({bits_1h:.0f} bits) 대비
    2048 bits 키는 약 {2048/bits_1h:.0f} 배 더 큰 소수를 사용
    -> BSGS 소요 시간 약 2^((2048-{bits_1h:.0f})/2) 배 증가
       = 2^{(2048 - bits_1h)/2:.0f} 배  (사실상 해독 불가능)
  ================================================================
""")
