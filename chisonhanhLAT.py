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
# PARITY
# =========================
def parity(x):
    return bin(x).count("1") & 1


# =========================
# TÍNH LAT
# =========================
LAT = [[0]*size for _ in range(size)]

for a in range(size):
    for b in range(size):

        s = 0

        for x in range(size):

            if parity(a & x) == parity(b & S[x]):
                s += 1
            else:
                s -= 1

        LAT[a][b] = s


# =========================
# LINEAR BRANCH NUMBER
# =========================
branch_lat = 100

for a in range(1,size):
    for b in range(1,size):

        if LAT[a][b] != 0:
            branch_lat = min(branch_lat, hw(a) + hw(b))

print("Linear Branch Number =", branch_lat)