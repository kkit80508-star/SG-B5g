import hashlib
import secrets
import time


def H1(data: str, n: int) -> int:
    """Hash to Z*_n"""
    digest = hashlib.sha256(data.encode()).hexdigest()
    return int(digest, 16) % n


def modinv(a, m):
    """Modular inverse"""
    return pow(a, -1, m)
    
# -----------------------------
# RSA Setup 
# -----------------------------

def generate_rsa(bits=512):
    from sympy import randprime

    p = randprime(2**(bits//2 - 1), 2**(bits//2))
    q = randprime(2**(bits//2 - 1), 2**(bits//2))
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if phi % e == 0:
        e = 3

    d = modinv(e, phi)

    # generator in Z*_n (simplified choice)
    g = 2

    MPK = (n, e, g)
    MSK = d
    return MPK, MSK


# -----------------------------
# KeyGen
# -----------------------------

def keygen(ID, MSK, n, g):
    h = H1(ID, n)
    sk = pow(h, MSK, n)          # sk = h^d mod n
    pk = pow(g, sk, n)           # pk = g^sk mod n
    return sk, pk


# -----------------------------
# Location Proof 
# -----------------------------

def generate_location_proof(ID, pos, L):
    """
    Simulates AP-based location proof π.
    """
    ts = int(time.time())

    ap_signatures = []
    for ap_id in range(5):  # assume 5 APs
        msg = f"{ID}|{ts}|{pos}|{secrets.token_hex(4)}"
        sig = hashlib.sha256(msg.encode()).hexdigest()
        ap_signatures.append((ap_id, sig))

    π = {
        "position": pos,
        "timestamp": ts,
        "ap_sigs": ap_signatures,
        "error_eps": 5,
        "region": L
    }

    return π


def verify_location_proof(π, L):
    return π["region"] == L


# -----------------------------
# Signing
# -----------------------------

def sign_message(m, sk, π, ts, r, n):
    c = H1(m + str(π) + str(ts) + str(r), n)
    sigma = pow(sk, c, n)   # σ = sk^c mod n
    return sigma, c


# -----------------------------
# Verification
# -----------------------------

def verify(m, sigma, π, ts, r, ID, MPK, authorized_IDs, L):
    n, e, g = MPK

    # 1. timestamp check (±5 sec)
    if abs(int(time.time()) - ts) > 5:
        return False

    # 2. check ID authorized
    if ID not in authorized_IDs:
        return False

    # 3. recompute h
    h = H1(ID, n)

    # 4. recompute c
    c = H1(m + str(π) + str(ts) + str(r), n)

    # 5. verify signature: σ^e ≡ h^c mod n
    if pow(sigma, e, n) != pow(h, c, n):
        return False

    # 6. verify location proof
    if not verify_location_proof(π, L):
        return False

    return True


# -----------------------------
# Example Usage
# -----------------------------

if __name__ == "__main__":
    MPK, MSK = generate_rsa()
    n, e, g = MPK

    ID = "turbine_001"
    authorized_IDs = [ID]
    L = "offshore_zone_A"

    sk, pk = keygen(ID, MSK, n, g)

    m = "power_status_update"
    ts = int(time.time())
    r = secrets.token_hex(8)

    π = generate_location_proof(ID, pos=(52.3, 4.9), L=L)

    sigma, c = sign_message(m, sk, π, ts, r, n)

    result = verify(m, sigma, π, ts, r, ID, MPK, authorized_IDs, L)

    print("Signature valid?", result)
