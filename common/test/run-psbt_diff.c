#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/psbt.h>
#include <bitcoin/tx.h>
#include <common/setup.h>
#include <stdio.h>
#include <wire/wire.h>
#include "../amount.c"
#include "../psbt_open.c"

/* AUTOGENERATED MOCKS START */
/* Generated stub for fromwire */
const u8 *fromwire(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, void *copy UNNEEDED, size_t n UNNEEDED)
{ fprintf(stderr, "fromwire called!\n"); abort(); }
/* Generated stub for fromwire_bool */
bool fromwire_bool(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_bool called!\n"); abort(); }
/* Generated stub for fromwire_fail */
void *fromwire_fail(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_fail called!\n"); abort(); }
/* Generated stub for fromwire_secp256k1_ecdsa_signature */
void fromwire_secp256k1_ecdsa_signature(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
					secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "fromwire_secp256k1_ecdsa_signature called!\n"); abort(); }
/* Generated stub for fromwire_sha256 */
void fromwire_sha256(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "fromwire_sha256 called!\n"); abort(); }
/* Generated stub for fromwire_tal_arrn */
u8 *fromwire_tal_arrn(const tal_t *ctx UNNEEDED,
		       const u8 **cursor UNNEEDED, size_t *max UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_tal_arrn called!\n"); abort(); }
/* Generated stub for fromwire_u16 */
u16 fromwire_u16(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u16 called!\n"); abort(); }
/* Generated stub for fromwire_u32 */
u32 fromwire_u32(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u32 called!\n"); abort(); }
/* Generated stub for fromwire_u64 */
u64 fromwire_u64(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u64 called!\n"); abort(); }
/* Generated stub for fromwire_u8 */
u8 fromwire_u8(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u8 called!\n"); abort(); }
/* Generated stub for towire */
void towire(u8 **pptr UNNEEDED, const void *data UNNEEDED, size_t len UNNEEDED)
{ fprintf(stderr, "towire called!\n"); abort(); }
/* Generated stub for towire_bool */
void towire_bool(u8 **pptr UNNEEDED, bool v UNNEEDED)
{ fprintf(stderr, "towire_bool called!\n"); abort(); }
/* Generated stub for towire_secp256k1_ecdsa_signature */
void towire_secp256k1_ecdsa_signature(u8 **pptr UNNEEDED,
			      const secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "towire_secp256k1_ecdsa_signature called!\n"); abort(); }
/* Generated stub for towire_sha256 */
void towire_sha256(u8 **pptr UNNEEDED, const struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "towire_sha256 called!\n"); abort(); }
/* Generated stub for towire_u16 */
void towire_u16(u8 **pptr UNNEEDED, u16 v UNNEEDED)
{ fprintf(stderr, "towire_u16 called!\n"); abort(); }
/* Generated stub for towire_u32 */
void towire_u32(u8 **pptr UNNEEDED, u32 v UNNEEDED)
{ fprintf(stderr, "towire_u32 called!\n"); abort(); }
/* Generated stub for towire_u64 */
void towire_u64(u8 **pptr UNNEEDED, u64 v UNNEEDED)
{ fprintf(stderr, "towire_u64 called!\n"); abort(); }
/* Generated stub for towire_u8 */
void towire_u8(u8 **pptr UNNEEDED, u8 v UNNEEDED)
{ fprintf(stderr, "towire_u8 called!\n"); abort(); }
/* Generated stub for towire_u8_array */
void towire_u8_array(u8 **pptr UNNEEDED, const u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_u8_array called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

static void diff_count(struct wally_psbt *a,
		       struct wally_psbt *b,
		       size_t diff_added,
		       size_t diff_rm)
{
	bool has_diff;
	struct input_set *added_in, *rm_in;
	struct output_set *added_out, *rm_out;

	has_diff = psbt_has_diff(tmpctx, a, b,
				 &added_in, &rm_in,
				 &added_out, &rm_out);

	assert(has_diff == (diff_added + diff_rm != 0));
	assert(tal_count(added_in) == diff_added);
	assert(tal_count(added_out) == diff_added);
	assert(tal_count(rm_in) == diff_rm);
	assert(tal_count(rm_out) == diff_rm);
}

static void add_in_out_with_serial(struct wally_psbt *psbt,
				   size_t serial_id,
				   size_t default_value)
{
	struct bitcoin_txid txid;
	u8 *script;
	struct amount_sat sat;
	struct wally_psbt_input *in;
	struct wally_psbt_output *out;

	memset(&txid, default_value, sizeof(txid));
	in = psbt_append_input(psbt, &txid, default_value, default_value,
			       NULL, NULL, NULL);
	if (!in)
		abort();
	psbt_input_add_serial_id(in, serial_id);

	script = tal_arr(tmpctx, u8, 20);
	memset(script, default_value, 20);
	sat = amount_sat(default_value);
	out = psbt_append_output(psbt, script, sat);
	if (!out)
		abort();
	psbt_output_add_serial_id(out, serial_id);
}

int main(int argc, const char *argv[])
{
	common_setup(argv[0]);

	struct wally_psbt *start, *end;
	u32 flags = 0;

	chainparams = chainparams_for_network("bitcoin");

	/* Create two psbts! */
	end = create_psbt(tmpctx, 1, 1, 0);
	if (wally_psbt_clone_alloc(end, flags, &start) != WALLY_OK)
		abort();
	diff_count(start, end, 0, 0);
	diff_count(end, start, 0, 0);

	/* New input/output added */
	add_in_out_with_serial(end, 10, 1);
	diff_count(start, end, 1, 0);
	diff_count(end, start, 0, 1);

	/* Add another one, before previous */
	if (wally_psbt_clone_alloc(end, flags, &start) != WALLY_OK)
		abort();
	add_in_out_with_serial(end, 5, 2);
	diff_count(start, end, 1, 0);
	diff_count(end, start, 0, 1);

	/* Add another, at end */
	if (wally_psbt_clone_alloc(end, flags, &start) != WALLY_OK)
		abort();
	add_in_out_with_serial(end, 15, 3);
	diff_count(start, end, 1, 0);
	diff_count(end, start, 0, 1);

	/* Add another, in middle */
	if (wally_psbt_clone_alloc(end, flags, &start) != WALLY_OK)
		abort();
	add_in_out_with_serial(end, 11, 4);
	diff_count(start, end, 1, 0);
	diff_count(end, start, 0, 1);

	/* Change existing input/output info
	 * (we accomplish this by removing and then
	 * readding an input/output with the same serial_id
	 * but different value) */
	if (wally_psbt_clone_alloc(end, flags, &start) != WALLY_OK)
		abort();
	psbt_rm_output(end, 0);
	psbt_rm_input(end, 0);
	add_in_out_with_serial(end, 5, 5);
	diff_count(start, end, 1, 1);
	diff_count(end, start, 1, 1);

	/* Add some extra unknown info to a PSBT */
	psbt_input_add_max_witness_len(&end->inputs[1], 100);
	psbt_input_add_max_witness_len(&start->inputs[1], 100);

	/* Swap locations */
	struct wally_map_item tmp;
	tmp = end->inputs[1].unknowns.items[0];
	end->inputs[1].unknowns.items[0] = end->inputs[1].unknowns.items[1];
	end->inputs[1].unknowns.items[1] = tmp;

	/* We expect nothing to change ? */
	/* FIXME: stable ordering of unknowns ? */
	diff_count(start, end, 1, 1);
	diff_count(end, start, 1, 1);

	/* No memory leaks please */
	common_shutdown();
	return 0;
}
