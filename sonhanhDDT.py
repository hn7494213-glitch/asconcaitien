# =========================
# S-box (5-bit)
# =========================
S = [
0x1f,0x02,0x04,0x0b,0x08,0x14,0x16,0x18,
0x10,0x05,0x09,0x0e,0x0d,0x19,0x11,0x17,
0x01,0x15,0x0a,0x0c,0x12,0x07,0x1c,0x1b,
0x1a,0x06,0x13,0x1d,0x03,0x1e,0x0f,0x00
]

n = 5
size = 2**n

# =========================
# HAMMING WEIGHT
# =========================
def hw(x):
    return bin(x).count("1")

# =========================
# TÍNH DDT
# =========================
DDT = [[0]*size for _ in range(size)]

for x in range(size):
    for dx in range(size):

        dy = S[x] ^ S[x ^ dx]
        DDT[dx][dy] += 1


# =========================
# DIFFERENTIAL BRANCH NUMBER
# =========================
branch_diff = 100

for dx in range(1,size):
    for dy in range(1,size):

        if DDT[dx][dy] > 0:
            branch_diff = min(branch_diff, hw(dx) + hw(dy))

print("Differential Branch Number =", branch_diff)