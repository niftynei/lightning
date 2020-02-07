#ifndef LIGHTNING_COMMON_PODLE_H
#define LIGHTNING_COMMON_PODLE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

/* derive_NUMS_point_at - Find the starting NUMS point for
 * a Proof of Discrete Log Equivalence, given an index.
 * @index - (in) index of NUM to generate
 * @nums_key - (out) pubkey of NUMs generated point
 */
bool derive_NUMS_point_at(u8 index, struct pubkey *nums_key);

#endif /* LIGHTNING_COMMON_PODLE_H */
