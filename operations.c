#include <stdio.h>
#include <pbc/pbc.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <time.h>

/* ================= GLOBALS ================= */
pairing_t pairing;

element_t x, y, r;
element_t P, Q, result_add;

/* ================= TIMER ================= */
double get_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* ================= SETUP ================= */
void setup() {
    pbc_param_t param;

    pbc_param_init_a_gen(param, 160, 512);

    pairing_init_pbc_param(pairing, param);

    printf("Pairing initialized successfully.\n");

    pbc_param_clear(param);
}

/* ================= PAIRING ================= */
void bilinearPairing() {
    int n = 10;
    double ttotal = 0.0;

    element_init_G1(x, pairing);
    element_init_G1(y, pairing);
    element_init_GT(r, pairing);

    for (int i = 0; i < n; i++) {
        element_random(x);
        element_random(y);

        double t0 = get_time();
        pairing_apply(r, x, y, pairing);
        double t1 = get_time();

        ttotal += (t1 - t0);
    }

    printf("Average Pairing Time T1 = %f ms\n", ttotal / n);
}

/* ================= G1 ADDITION ================= */
void additionG1() {
    int n = 10;
    double ttotal = 0.0;

    element_init_G1(P, pairing);
    element_init_G1(Q, pairing);
    element_init_G1(result_add, pairing);

    for (int i = 0; i < n; i++) {
        element_random(P);
        element_random(Q);

        double t0 = get_time();
        element_add(result_add, P, Q);
        double t1 = get_time();

        ttotal += (t1 - t0);
    }

    printf("Average G1 Addition Time T2 = %f ms\n", ttotal / n);
}

/* ================= SCALAR MULTIPLICATION ================= */
void scalar_multiply() {
    int n = 10;
    double ttotal = 0.0;

    element_t scalar, P1, result;

    element_init_Zr(scalar, pairing);
    element_init_G1(P1, pairing);
    element_init_G1(result, pairing);

    for (int i = 0; i < n; i++) {
        element_random(scalar);
        element_random(P1);

        double t0 = get_time();
        element_mul_zn(result, P1, scalar);
        double t1 = get_time();

        ttotal += (t1 - t0);
    }

    printf("Average Scalar Multiplication T4 = %f ms\n", ttotal / n);
}

/* ================= EXPONENTIATION IN G1 ================= */
void exponentiate_in_Zq() {
    int n = 10;
    double ttotal = 0.0;

    element_t base, exponent, result;

    element_init_G1(base, pairing);
    element_init_Zr(exponent, pairing);
    element_init_G1(result, pairing);

    for (int i = 0; i < n; i++) {
        element_random(base);
        element_random(exponent);

        double t0 = get_time();
        element_pow_zn(result, base, exponent);
        double t1 = get_time();

        ttotal += (t1 - t0);
    }

    printf("Average Exponentiation Time T5 = %f ms\n", ttotal / n);
}

/* ================= HASH TO G1 ================= */
void H1(const unsigned char *bitstring) {
    int n = 10;
    double ttotal = 0.0;

    unsigned char hash[SHA256_DIGEST_LENGTH];

    element_t result;
    element_init_G1(result, pairing);

    for (int i = 0; i < n; i++) {

        SHA256(bitstring, strlen((char*)bitstring), hash);

        double t0 = get_time();
        element_from_hash(result, hash, SHA256_DIGEST_LENGTH);
        double t1 = get_time();

        ttotal += (t1 - t0);
    }

    printf("Average H1 Execution Time T6 = %f ms\n", ttotal / n);
}

/* ================= RSA MODULAR EXPONENTIATION ================= */
void rsa_exponentiation() {
    int n = 10;
    double ttotal = 0.0;

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *base = BN_new();
    BIGNUM *exp = BN_new();
    BIGNUM *mod = BN_new();
    BIGNUM *result = BN_new();

    // e = 65537
    BN_set_word(exp, 65537);

    // generate 2048-bit modulus (for benchmark)
    BN_generate_prime_ex(mod, 2048, 0, NULL, NULL, NULL);

    for (int i = 0; i < n; i++) {

        BN_rand_range(base, mod);

        double t0 = get_time();
        BN_mod_exp(result, base, exp, mod, ctx);
        double t1 = get_time();

        ttotal += (t1 - t0);
    }

    printf("Average RSA Exponentiation T_RSA = %f ms\n", ttotal / n);

    BN_free(base);
    BN_free(exp);
    BN_free(mod);
    BN_free(result);
    BN_CTX_free(ctx);
}

/* ================= MAIN ================= */
int main() {

    setup();

    bilinearPairing();
    additionG1();
    scalar_multiply();
    exponentiate_in_Zq();

    unsigned char bitstring[] = "011010100110101011011";
    H1(bitstring);

    rsa_exponentiation();

    element_clear(x);
    element_clear(y);
    element_clear(r);

    element_clear(P);
    element_clear(Q);
    element_clear(result_add);

    pairing_clear(pairing);

    printf("All computations completed successfully.\n");

    return 0;
}
