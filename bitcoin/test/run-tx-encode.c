#include <assert.h>
#include <bitcoin/psbt.c>
#include <bitcoin/pullpush.c>
#include <bitcoin/shadouble.c>
#include <bitcoin/tx.c>
#include <bitcoin/varint.c>
#include <ccan/str/hex/hex.h>
#include <common/setup.h>
#include <common/utils.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for amount_asset_is_main */
bool amount_asset_is_main(struct amount_asset *asset UNNEEDED)
{ fprintf(stderr, "amount_asset_is_main called!\n"); abort(); }
/* Generated stub for amount_asset_to_sat */
struct amount_sat amount_asset_to_sat(struct amount_asset *asset UNNEEDED)
{ fprintf(stderr, "amount_asset_to_sat called!\n"); abort(); }
/* Generated stub for amount_sat_add */
 bool amount_sat_add(struct amount_sat *val UNNEEDED,
				       struct amount_sat a UNNEEDED,
				       struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_add called!\n"); abort(); }
/* Generated stub for amount_sat_eq */
bool amount_sat_eq(struct amount_sat a UNNEEDED, struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_eq called!\n"); abort(); }
/* Generated stub for amount_sat_sub */
 bool amount_sat_sub(struct amount_sat *val UNNEEDED,
				       struct amount_sat a UNNEEDED,
				       struct amount_sat b UNNEEDED)
{ fprintf(stderr, "amount_sat_sub called!\n"); abort(); }
/* Generated stub for fromwire */
const u8 *fromwire(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, void *copy UNNEEDED, size_t n UNNEEDED)
{ fprintf(stderr, "fromwire called!\n"); abort(); }
/* Generated stub for fromwire_amount_sat */
struct amount_sat fromwire_amount_sat(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_amount_sat called!\n"); abort(); }
/* Generated stub for fromwire_fail */
void *fromwire_fail(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_fail called!\n"); abort(); }
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
/* Generated stub for towire_amount_sat */
void towire_amount_sat(u8 **pptr UNNEEDED, const struct amount_sat sat UNNEEDED)
{ fprintf(stderr, "towire_amount_sat called!\n"); abort(); }
/* Generated stub for towire_sha256 */
void towire_sha256(u8 **pptr UNNEEDED, const struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "towire_sha256 called!\n"); abort(); }
/* Generated stub for towire_u16 */
void towire_u16(u8 **pptr UNNEEDED, u16 v UNNEEDED)
{ fprintf(stderr, "towire_u16 called!\n"); abort(); }
/* Generated stub for towire_u32 */
void towire_u32(u8 **pptr UNNEEDED, u32 v UNNEEDED)
{ fprintf(stderr, "towire_u32 called!\n"); abort(); }
/* Generated stub for towire_u8_array */
void towire_u8_array(u8 **pptr UNNEEDED, const u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_u8_array called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

const char extended_tx[] =
    "02000000000101b5bef485c41d0d1f58d1e8a561924ece5c476d86cff063ea10c8df06136e"
    "b31d00000000171600144aa38e396e1394fb45cbf83f48d1464fbc9f498fffffffff014033"
    "0f000000000017a9140580ba016669d3efaf09a0b2ec3954469ea2bf038702483045022100"
    "f2abf9e9cf238c66533af93f23937eae8ac01fb6f105a00ab71dbefb9637dc9502205c1ac7"
    "45829b3f6889607961f5d817dfa0c8f52bdda12e837c4f7b162f6db8a701210204096eb817"
    "f7efb414ef4d3d8be39dd04374256d3b054a322d4a6ee22736d03b00000000";

static void hexeq(const void *p, size_t len, const char *hex)
{
	char *tmphex = tal_hexstr(NULL, p, len);

	if (!streq(hex, tmphex)) {
		fprintf(stderr, "Expected '%s' got '%s'", hex, tmphex);
		abort();
	}
	tal_free(tmphex);
}

int main(int argc, const char *argv[])
{
	common_setup(argv[0]);
	chainparams = chainparams_for_network("bitcoin");

	struct bitcoin_tx *tx;

	tx = bitcoin_tx_from_hex(NULL, extended_tx, strlen(extended_tx));
	assert(tx);

	/* Canonical results from Nichola Dorier's
	 *	   http://n.bitcoin.ninja/checktx
	 * With much thanks!
	 */
	assert(tx->wtx->num_inputs == 1);
	assert(tx->wtx->num_outputs == 1);

	reverse_bytes(tx->wtx->inputs[0].txhash,
		      sizeof(tx->wtx->inputs[0].txhash));
	hexeq(tx->wtx->inputs[0].txhash, sizeof(tx->wtx->inputs[0].txhash),
	      "1db36e1306dfc810ea63f0cf866d475cce4e9261a5e8d1581f0d1dc485f4beb5");
	assert(tx->wtx->inputs[0].index == 0);

	/* This is a p2sh-p2wpkh: */
	/* ScriptSig is push of "version 0 + hash of pubkey" */
	hexeq(tx->wtx->inputs[0].script, tx->wtx->inputs[0].script_len,
	      "16" "00" "144aa38e396e1394fb45cbf83f48d1464fbc9f498f");

	/* Witness with 2 items */
	assert(tx->wtx->inputs[0].witness);
	assert(tx->wtx->inputs[0].witness->num_items == 2);

	hexeq(tx->wtx->inputs[0].witness->items[0].witness,
	      tx->wtx->inputs[0].witness->items[0].witness_len,
	      "3045022100f2abf9e9cf238c66533af93f23937eae8ac01fb6f105a00ab71dbe"
	      "fb9637dc9502205c1ac745829b3f6889607961f5d817dfa0c8f52bdda12e837c"
	      "4f7b162f6db8a701");
	hexeq(tx->wtx->inputs[0].witness->items[1].witness,
	      tx->wtx->inputs[0].witness->items[1].witness_len,
	      "0204096eb817f7efb414ef4d3d8be39dd04374256d3b054a322d4a6ee22736d0"
	      "3b");

	tal_free(tx);
	common_shutdown();
	return 0;
}
