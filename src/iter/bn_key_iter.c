//
// Created by cp723 on 2/1/2019.
//

#include "bn_key_iter.h"

#include <stdlib.h>

bn_key_iter* bn_key_iter_create(BN_CTX *ctx, const unsigned char *key, size_t key_size,
        const bn *first_perm, const bn *last_perm) {
    bn_key_iter *iter;
    if((iter = malloc(sizeof(*iter))) == NULL) {
        return NULL;
    }

    iter->curr_perm = BN_CTX_get(ctx);
    iter->last_perm = BN_CTX_get(ctx);
    iter->t = BN_CTX_get(ctx);
    iter->tmp = BN_CTX_get(ctx);
    iter->key_mpz = BN_CTX_get(ctx);
    iter->corrupted_key_bn = BN_CTX_get(ctx);

    if(iter->corrupted_key_bn == NULL) {
        return NULL;
    }

    BN_copy(iter->curr_perm, first_perm);
    BN_copy(iter->last_perm, last_perm);

    BN_bin2bn(uncom_pub_key, key_size, iter->key_bn)

    // Perform an XOR operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    mpz_xor(iter->corrupted_key_mpz, iter->key_mpz, iter->curr_perm);

    return iter;
}

void bn_key_iter_destroy(bn_key_iter *iter) {
    mpz_clears(iter->curr_perm, iter->last_perm, iter->t, iter->tmp, iter->key_mpz,
            iter->corrupted_key_mpz, NULL);
    free(iter);
}

void bn_key_iter_next(bn_key_iter *iter) {
    // Equivalent to: t = (perm | (perm - 1)) + 1
    mpz_sub_ui(iter->t, iter->curr_perm, 1);
    mpz_ior(iter->t, iter->curr_perm, iter->t);
    mpz_add_ui(iter->t, iter->t, 1);

    // Equivalent to: perm = t | ((((t & -t) / (perm & -perm)) >> 1) - 1)
    mpz_neg(iter->tmp, iter->curr_perm);
    mpz_and(iter->curr_perm, iter->curr_perm, iter->tmp);

    mpz_neg(iter->tmp, iter->t);
    mpz_and(iter->tmp, iter->t, iter->tmp);

    // Truncate divide
    mpz_tdiv_q(iter->tmp, iter->tmp, iter->curr_perm);
    // Right shift by 1
    mpz_tdiv_q_2exp(iter->tmp, iter->tmp, 1);
    mpz_sub_ui(iter->tmp, iter->tmp, 1);
    mpz_ior(iter->curr_perm, iter->t, iter->tmp);

    // Perform an XOR operation between the permutation and the key.
    // If a bit is set in permutation, then flip the bit in the key.
    // Otherwise, leave it as is.
    mpz_xor(iter->corrupted_key_mpz, iter->key_mpz, iter->curr_perm);
}

void bn_key_iter_get(const bn_key_iter *iter, unsigned char *corrupted_key) {
    // Convert from mpz to an unsigned char array
    mpz_export(corrupted_key, NULL, sizeof(*corrupted_key), 1, 0, 0, iter->corrupted_key_mpz);
}
