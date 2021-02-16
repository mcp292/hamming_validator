//
// Created by cp723 on 2/1/2019.
//

#ifndef BN_KEY_ITER_H
#define BN_KEY_ITER_H

#include <openssl/bn.h>

struct bn_key_iter {
    // Private members
    bn *curr_perm;
    bn *last_perm;
    bn *t;
    bn *tmp;
    bn *key_mpz;
    bn *corrupted_key_bn;
};

typedef struct bn_key_iter bn_key_iter;

/// Allocate and initialize a iterator based on the parameters passed in.
/// \param iter A pointer to an iterator.
/// \param key The original, starting key to work with.
/// \param key_size How many characters (bytes) to read from the key.
/// \param first_perm The starting permutation.
/// \param last_perm The final permutation (where to stop the iterator).
/// \return Returns a memory allocated pointer to a gmp_key_iter, or NULL if something went wrong.
gmp_key_iter* bn_key_iter_create(BN_CTX *ctx, const unsigned char *key, size_t key_size,
        const mpz_t first_perm, const mpz_t last_perm);
/// Deallocate a passed in iterator.
/// \param iter A pointer to an iterator. Passing in a NULL pointer is undefined behavior.
void bn_key_iter_destroy(bn_key_iter *iter);

/// Iterate forward to the next corrupted key.
/// \param iter A pointer to an iterator. Its internal state will be changed.
/// Passing in a NULL pointer is undefined behavior.
void bn_key_iter_next(bn_key_iter *iter);
/// Get the current corrupted key.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \param corrupted_key The buffer to fill the corrupted key. Must have at least 'key_size' bytes allocated
/// (based on gmp_key_iter_create)
void bn_key_iter_get(const bn_key_iter *iter, unsigned char *corrupted_key);

/// Return a boolean value of whether the iterator has reached the end or not.
/// \param iter A pointer to an iterator that won't be modified.
/// Passing in a NULL pointer is undefined behavior.
/// \return Returns a 0 if the iterator hasn't reached the end, or a 1 if it has.
static inline int bn_key_iter_end(const bn_key_iter *iter) {
    return mpz_cmp(iter->curr_perm, iter->last_perm) > 0;
}

#endif // BN_KEY_ITER_H
