#ifndef LIGHTNING_COMMON_PODLE_H
#define LIGHTNING_COMMON_PODLE_H
#include "config.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <common/node_id.h>
#include <stdbool.h>

struct proof_dle {
	struct pubkey pk2;
	struct sha256 commitment;
	u8 sig[32];
	struct sha256 e;
};

/* derive_NUMS_point_at - Find the starting NUMS point for
 * a Proof of Discrete Log Equivalence, given an index.
 * @index - (in) index of NUM to generate
 * @nums_key - (out) pubkey of NUMs generated point
 */
bool derive_NUMS_point_at(u8 index, struct pubkey *nums_key);

/* generate_proof_of_dle - Given a private key and a
 * secondary generator point, j, compute the proof of discrete
 * log equivalence for this private key
 *
 * @privkey - (in) the private key to calculate the podle for
 * @j       - (in) the second generator point
 * @node_id - (in) the destination node's id
 * @podle   - (out) commitment, etc
 */
bool generate_proof_of_dle(struct privkey *privkey, struct pubkey *j,
			   struct node_id *node_id, struct proof_dle *podle);

/* verify_proof_of_dle - Given the pubkey for the utxo, the generator
 * point J, and the podle information, verify that it's a correct
 * proof.
 *
 * @p     - (in) the pubkey of the utxo
 * @j     - (in) the second generator point used for calculating the proof
 * @podle - (in) the proof of discrete log equivalence info
 */
bool verify_proof_of_dle(struct pubkey *p, struct pubkey *j,
			 struct node_id *node_id, struct proof_dle *podle);
#endif /* LIGHTNING_COMMON_PODLE_H */
