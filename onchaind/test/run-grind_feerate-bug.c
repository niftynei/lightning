/* Bug https://github.com/ElementsProject/lightning/issues/2820
 *
 No valid signature found for 3 htlc_timeout_txs feerate 10992-15370, last tx 0200000001a02a38c6ec5541963704a2a035b3094b18d69cc25cc7419d75e02894618329720000000000000000000191ea3000000000002200208bfadb3554f41cc06f00de0ec2e2f91e36ee45b5006a1f606146784755356ba532f10800, input 3215967sat, signature 3045022100917efdc8577e8578aef5e513fad25edbb55921466e8ffccb05ce8bb05a54ae6902205c2fded9d7bfc290920821bfc828720bc24287f3dad9a62fb4f806e2404ed0f401, cltvs 585998/585998/586034 wscripts 76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868/76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868/76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868 (version v0.7.1-57-gb3215a8)"
*/
#include <ccan/str/hex/hex.h>

#define main test_main
int test_main(int argc, char *argv[]);
#include "../onchaind.c"
#undef main

/* AUTOGENERATED MOCKS START */
/* Generated stub for commit_number_obscurer */
u64 commit_number_obscurer(const struct pubkey *opener_payment_basepoint UNNEEDED,
			   const struct pubkey *accepter_payment_basepoint UNNEEDED)
{ fprintf(stderr, "commit_number_obscurer called!\n"); abort(); }
/* Generated stub for daemon_shutdown */
void daemon_shutdown(void)
{ fprintf(stderr, "daemon_shutdown called!\n"); abort(); }
/* Generated stub for derive_keyset */
bool derive_keyset(const struct pubkey *per_commitment_point UNNEEDED,
		   const struct basepoints *self UNNEEDED,
		   const struct basepoints *other UNNEEDED,
		   bool option_static_remotekey UNNEEDED,
		   struct keyset *keyset UNNEEDED)
{ fprintf(stderr, "derive_keyset called!\n"); abort(); }
/* Generated stub for dump_memleak */
bool dump_memleak(struct htable *memtable UNNEEDED)
{ fprintf(stderr, "dump_memleak called!\n"); abort(); }
/* Generated stub for fromwire_fail */
const void *fromwire_fail(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_fail called!\n"); abort(); }
/* Generated stub for fromwire_hsm_get_per_commitment_point_reply */
bool fromwire_hsm_get_per_commitment_point_reply(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, struct pubkey *per_commitment_point UNNEEDED, struct secret **old_commitment_secret UNNEEDED)
{ fprintf(stderr, "fromwire_hsm_get_per_commitment_point_reply called!\n"); abort(); }
/* Generated stub for fromwire_onchain_depth */
bool fromwire_onchain_depth(const void *p UNNEEDED, struct bitcoin_txid *txid UNNEEDED, u32 *depth UNNEEDED, bool *is_replay UNNEEDED)
{ fprintf(stderr, "fromwire_onchain_depth called!\n"); abort(); }
/* Generated stub for fromwire_onchain_dev_memleak */
bool fromwire_onchain_dev_memleak(const void *p UNNEEDED)
{ fprintf(stderr, "fromwire_onchain_dev_memleak called!\n"); abort(); }
/* Generated stub for fromwire_onchain_htlc */
bool fromwire_onchain_htlc(const void *p UNNEEDED, struct htlc_stub *htlc UNNEEDED, bool *tell_if_missing UNNEEDED, bool *tell_immediately UNNEEDED)
{ fprintf(stderr, "fromwire_onchain_htlc called!\n"); abort(); }
/* Generated stub for fromwire_onchain_init */
bool fromwire_onchain_init(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, struct shachain *shachain UNNEEDED, const struct chainparams **chainparams UNNEEDED, struct amount_sat *funding_amount_satoshi UNNEEDED, struct amount_msat *our_msat UNNEEDED, struct pubkey *old_remote_per_commitment_point UNNEEDED, struct pubkey *remote_per_commitment_point UNNEEDED, u32 *local_to_self_delay UNNEEDED, u32 *remote_to_self_delay UNNEEDED, u32 *delayed_to_us_feerate UNNEEDED, u32 *htlc_feerate UNNEEDED, u32 *penalty_feerate UNNEEDED, struct amount_sat *local_dust_limit_satoshi UNNEEDED, struct bitcoin_txid *our_broadcast_txid UNNEEDED, u8 **local_scriptpubkey UNNEEDED, u8 **remote_scriptpubkey UNNEEDED, struct pubkey *ourwallet_pubkey UNNEEDED, enum side *opener UNNEEDED, struct basepoints *local_basepoints UNNEEDED, struct basepoints *remote_basepoints UNNEEDED, struct bitcoin_tx **tx UNNEEDED, u32 *tx_blockheight UNNEEDED, u32 *reasonable_depth UNNEEDED, secp256k1_ecdsa_signature **htlc_signature UNNEEDED, u64 *num_htlcs UNNEEDED, u32 *min_possible_feerate UNNEEDED, u32 *max_possible_feerate UNNEEDED, struct pubkey **possible_remote_per_commit_point UNNEEDED, bool *option_static_remotekey UNNEEDED, bool *is_replay UNNEEDED)
{ fprintf(stderr, "fromwire_onchain_init called!\n"); abort(); }
/* Generated stub for fromwire_onchain_known_preimage */
bool fromwire_onchain_known_preimage(const void *p UNNEEDED, struct preimage *preimage UNNEEDED, bool *is_replay UNNEEDED)
{ fprintf(stderr, "fromwire_onchain_known_preimage called!\n"); abort(); }
/* Generated stub for fromwire_onchain_spent */
bool fromwire_onchain_spent(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, struct bitcoin_tx **tx UNNEEDED, u32 *input_num UNNEEDED, u32 *blockheight UNNEEDED, bool *is_replay UNNEEDED)
{ fprintf(stderr, "fromwire_onchain_spent called!\n"); abort(); }
/* Generated stub for fromwire_peektype */
int fromwire_peektype(const u8 *cursor UNNEEDED)
{ fprintf(stderr, "fromwire_peektype called!\n"); abort(); }
/* Generated stub for fromwire_tal_arrn */
u8 *fromwire_tal_arrn(const tal_t *ctx UNNEEDED,
		       const u8 **cursor UNNEEDED, size_t *max UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_tal_arrn called!\n"); abort(); }
/* Generated stub for fromwire_u16 */
u16 fromwire_u16(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u16 called!\n"); abort(); }
/* Generated stub for htlc_offered_wscript */
u8 *htlc_offered_wscript(const tal_t *ctx UNNEEDED,
			 const struct ripemd160 *ripemd UNNEEDED,
			 const struct keyset *keyset UNNEEDED)
{ fprintf(stderr, "htlc_offered_wscript called!\n"); abort(); }
/* Generated stub for htlc_received_wscript */
u8 *htlc_received_wscript(const tal_t *ctx UNNEEDED,
			  const struct ripemd160 *ripemd UNNEEDED,
			  const struct abs_locktime *expiry UNNEEDED,
			  const struct keyset *keyset UNNEEDED)
{ fprintf(stderr, "htlc_received_wscript called!\n"); abort(); }
/* Generated stub for htlc_success_tx */
struct bitcoin_tx *htlc_success_tx(const tal_t *ctx UNNEEDED,
				   const struct chainparams *chainparams UNNEEDED,
				   const struct bitcoin_txid *commit_txid UNNEEDED,
				   unsigned int commit_output_number UNNEEDED,
				   struct amount_msat htlc_msatoshi UNNEEDED,
				   u16 to_self_delay UNNEEDED,
				   u32 feerate_per_kw UNNEEDED,
				   const struct keyset *keyset UNNEEDED)
{ fprintf(stderr, "htlc_success_tx called!\n"); abort(); }
/* Generated stub for master_badmsg */
void master_badmsg(u32 type_expected UNNEEDED, const u8 *msg)
{ fprintf(stderr, "master_badmsg called!\n"); abort(); }
/* Generated stub for memleak_enter_allocations */
struct htable *memleak_enter_allocations(const tal_t *ctx UNNEEDED,
					 const void *exclude1 UNNEEDED,
					 const void *exclude2 UNNEEDED)
{ fprintf(stderr, "memleak_enter_allocations called!\n"); abort(); }
/* Generated stub for memleak_remove_referenced */
void memleak_remove_referenced(struct htable *memtable UNNEEDED, const void *root UNNEEDED)
{ fprintf(stderr, "memleak_remove_referenced called!\n"); abort(); }
/* Generated stub for memleak_scan_region */
void memleak_scan_region(struct htable *memtable UNNEEDED,
			 const void *p UNNEEDED, size_t bytelen UNNEEDED)
{ fprintf(stderr, "memleak_scan_region called!\n"); abort(); }
/* Generated stub for new_coin_chain_fees */
struct chain_coin_mvt *new_coin_chain_fees(const tal_t *ctx UNNEEDED,
					   const char *account_name UNNEEDED,
					   const struct bitcoin_txid *tx_txid UNNEEDED,
					   u32 blockheight UNNEEDED,
					   struct amount_msat amount UNNEEDED,
					   enum mvt_unit_type unit UNNEEDED)
{ fprintf(stderr, "new_coin_chain_fees called!\n"); abort(); }
/* Generated stub for new_coin_chain_fees_sat */
struct chain_coin_mvt *new_coin_chain_fees_sat(const tal_t *ctx UNNEEDED,
					       const char *account_name UNNEEDED,
					       const struct bitcoin_txid *tx_txid UNNEEDED,
					       u32 blockheight UNNEEDED,
					       struct amount_sat amount UNNEEDED,
					       enum mvt_unit_type unit UNNEEDED)
{ fprintf(stderr, "new_coin_chain_fees_sat called!\n"); abort(); }
/* Generated stub for new_coin_journal_entry */
struct chain_coin_mvt *new_coin_journal_entry(const tal_t *ctx UNNEEDED,
					      const char *account_name UNNEEDED,
					      const struct bitcoin_txid *txid UNNEEDED,
					      const struct bitcoin_txid *out_txid UNNEEDED,
					      u32 vout UNNEEDED,
					      u32 blockheight UNNEEDED,
					      struct amount_msat amount UNNEEDED,
					      bool is_credit UNNEEDED,
					      enum mvt_unit_type unit UNNEEDED)
{ fprintf(stderr, "new_coin_journal_entry called!\n"); abort(); }
/* Generated stub for new_coin_onchain_htlc_sat */
struct chain_coin_mvt *new_coin_onchain_htlc_sat(const tal_t *ctx UNNEEDED,
	       					 const char *account_name UNNEEDED,
						 const struct bitcoin_txid *txid UNNEEDED,
						 const struct bitcoin_txid *out_txid UNNEEDED,
						 u32 vout UNNEEDED, struct sha256 payment_hash UNNEEDED,
						 u32 blockheight UNNEEDED,
						 struct amount_sat amount UNNEEDED,
						 bool is_credit UNNEEDED,
						 enum mvt_unit_type unit UNNEEDED)
{ fprintf(stderr, "new_coin_onchain_htlc_sat called!\n"); abort(); }
/* Generated stub for new_coin_penalty_sat */
struct chain_coin_mvt *new_coin_penalty_sat(const tal_t *ctx UNNEEDED,
					    const char *account_name UNNEEDED,
					    const struct bitcoin_txid *txid UNNEEDED,
					    const struct bitcoin_txid *out_txid UNNEEDED,
					    u32 vout UNNEEDED,
					    u32 blockheight UNNEEDED,
					    struct amount_sat amount UNNEEDED,
					    enum mvt_unit_type unit UNNEEDED)
{ fprintf(stderr, "new_coin_penalty_sat called!\n"); abort(); }
/* Generated stub for new_coin_withdrawal */
struct chain_coin_mvt *new_coin_withdrawal(const tal_t *ctx UNNEEDED,
					  const char *account_name UNNEEDED,
					  const struct bitcoin_txid *tx_txid UNNEEDED,
					  const struct bitcoin_txid *out_txid UNNEEDED,
					  u32 vout UNNEEDED,
					  u32 blockheight UNNEEDED,
					  struct amount_msat amount UNNEEDED,
					  enum mvt_unit_type unit UNNEEDED)
{ fprintf(stderr, "new_coin_withdrawal called!\n"); abort(); }
/* Generated stub for new_coin_withdrawal_sat */
struct chain_coin_mvt *new_coin_withdrawal_sat(const tal_t *ctx UNNEEDED,
					       const char *account_name UNNEEDED,
					       const struct bitcoin_txid *tx_txid UNNEEDED,
					       const struct bitcoin_txid *out_txid UNNEEDED,
					       u32 vout UNNEEDED,
					       u32 blockheight UNNEEDED,
					       struct amount_sat amount UNNEEDED,
					       enum mvt_unit_type unit UNNEEDED)
{ fprintf(stderr, "new_coin_withdrawal_sat called!\n"); abort(); }
/* Generated stub for notleak_ */
void *notleak_(const void *ptr UNNEEDED, bool plus_children UNNEEDED)
{ fprintf(stderr, "notleak_ called!\n"); abort(); }
/* Generated stub for onchain_wire_type_name */
const char *onchain_wire_type_name(int e UNNEEDED)
{ fprintf(stderr, "onchain_wire_type_name called!\n"); abort(); }
/* Generated stub for peer_billboard */
void peer_billboard(bool perm UNNEEDED, const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "peer_billboard called!\n"); abort(); }
/* Generated stub for shachain_get_secret */
bool shachain_get_secret(const struct shachain *shachain UNNEEDED,
			 u64 commit_num UNNEEDED,
			 struct secret *preimage UNNEEDED)
{ fprintf(stderr, "shachain_get_secret called!\n"); abort(); }
/* Generated stub for status_failed */
void status_failed(enum status_failreason code UNNEEDED,
		   const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "status_failed called!\n"); abort(); }
/* Generated stub for status_setup_sync */
void status_setup_sync(int fd UNNEEDED)
{ fprintf(stderr, "status_setup_sync called!\n"); abort(); }
/* Generated stub for subdaemon_setup */
void subdaemon_setup(int argc UNNEEDED, char *argv[])
{ fprintf(stderr, "subdaemon_setup called!\n"); abort(); }
/* Generated stub for to_self_wscript */
u8 *to_self_wscript(const tal_t *ctx UNNEEDED,
		    u16 to_self_delay UNNEEDED,
		    const struct keyset *keyset UNNEEDED)
{ fprintf(stderr, "to_self_wscript called!\n"); abort(); }
/* Generated stub for towire_hsm_get_per_commitment_point */
u8 *towire_hsm_get_per_commitment_point(const tal_t *ctx UNNEEDED, u64 n UNNEEDED)
{ fprintf(stderr, "towire_hsm_get_per_commitment_point called!\n"); abort(); }
/* Generated stub for towire_hsm_sign_delayed_payment_to_us */
u8 *towire_hsm_sign_delayed_payment_to_us(const tal_t *ctx UNNEEDED, u64 commit_num UNNEEDED, const struct bitcoin_tx *tx UNNEEDED, const u8 *wscript UNNEEDED, struct amount_sat input_amount UNNEEDED)
{ fprintf(stderr, "towire_hsm_sign_delayed_payment_to_us called!\n"); abort(); }
/* Generated stub for towire_hsm_sign_penalty_to_us */
u8 *towire_hsm_sign_penalty_to_us(const tal_t *ctx UNNEEDED, const struct secret *revocation_secret UNNEEDED, const struct bitcoin_tx *tx UNNEEDED, const u8 *wscript UNNEEDED, struct amount_sat input_amount UNNEEDED)
{ fprintf(stderr, "towire_hsm_sign_penalty_to_us called!\n"); abort(); }
/* Generated stub for towire_hsm_sign_remote_htlc_to_us */
u8 *towire_hsm_sign_remote_htlc_to_us(const tal_t *ctx UNNEEDED, const struct pubkey *remote_per_commitment_point UNNEEDED, const struct bitcoin_tx *tx UNNEEDED, const u8 *wscript UNNEEDED, struct amount_sat input_amount UNNEEDED)
{ fprintf(stderr, "towire_hsm_sign_remote_htlc_to_us called!\n"); abort(); }
/* Generated stub for towire_onchain_add_utxo */
u8 *towire_onchain_add_utxo(const tal_t *ctx UNNEEDED, const struct bitcoin_txid *prev_out_tx UNNEEDED, u32 prev_out_index UNNEEDED, const struct pubkey *per_commit_point UNNEEDED, struct amount_sat value UNNEEDED, u32 blockheight UNNEEDED, const u8 *scriptpubkey UNNEEDED)
{ fprintf(stderr, "towire_onchain_add_utxo called!\n"); abort(); }
/* Generated stub for towire_onchain_all_irrevocably_resolved */
u8 *towire_onchain_all_irrevocably_resolved(const tal_t *ctx UNNEEDED)
{ fprintf(stderr, "towire_onchain_all_irrevocably_resolved called!\n"); abort(); }
/* Generated stub for towire_onchain_annotate_txin */
u8 *towire_onchain_annotate_txin(const tal_t *ctx UNNEEDED, const struct bitcoin_txid *txid UNNEEDED, u32 innum UNNEEDED, enum wallet_tx_type type UNNEEDED)
{ fprintf(stderr, "towire_onchain_annotate_txin called!\n"); abort(); }
/* Generated stub for towire_onchain_annotate_txout */
u8 *towire_onchain_annotate_txout(const tal_t *ctx UNNEEDED, const struct bitcoin_txid *txid UNNEEDED, u32 outnum UNNEEDED, enum wallet_tx_type type UNNEEDED)
{ fprintf(stderr, "towire_onchain_annotate_txout called!\n"); abort(); }
/* Generated stub for towire_onchain_broadcast_tx */
u8 *towire_onchain_broadcast_tx(const tal_t *ctx UNNEEDED, const struct bitcoin_tx *tx UNNEEDED, enum wallet_tx_type type UNNEEDED)
{ fprintf(stderr, "towire_onchain_broadcast_tx called!\n"); abort(); }
/* Generated stub for towire_onchain_dev_memleak_reply */
u8 *towire_onchain_dev_memleak_reply(const tal_t *ctx UNNEEDED, bool leak UNNEEDED)
{ fprintf(stderr, "towire_onchain_dev_memleak_reply called!\n"); abort(); }
/* Generated stub for towire_onchain_extracted_preimage */
u8 *towire_onchain_extracted_preimage(const tal_t *ctx UNNEEDED, const struct preimage *preimage UNNEEDED)
{ fprintf(stderr, "towire_onchain_extracted_preimage called!\n"); abort(); }
/* Generated stub for towire_onchain_htlc_timeout */
u8 *towire_onchain_htlc_timeout(const tal_t *ctx UNNEEDED, const struct htlc_stub *htlc UNNEEDED)
{ fprintf(stderr, "towire_onchain_htlc_timeout called!\n"); abort(); }
/* Generated stub for towire_onchain_init_reply */
u8 *towire_onchain_init_reply(const tal_t *ctx UNNEEDED)
{ fprintf(stderr, "towire_onchain_init_reply called!\n"); abort(); }
/* Generated stub for towire_onchain_missing_htlc_output */
u8 *towire_onchain_missing_htlc_output(const tal_t *ctx UNNEEDED, const struct htlc_stub *htlc UNNEEDED)
{ fprintf(stderr, "towire_onchain_missing_htlc_output called!\n"); abort(); }
/* Generated stub for towire_onchain_notify_coin_mvt */
u8 *towire_onchain_notify_coin_mvt(const tal_t *ctx UNNEEDED, const struct chain_coin_mvt *mvt UNNEEDED)
{ fprintf(stderr, "towire_onchain_notify_coin_mvt called!\n"); abort(); }
/* Generated stub for towire_onchain_unwatch_tx */
u8 *towire_onchain_unwatch_tx(const tal_t *ctx UNNEEDED, const struct bitcoin_txid *txid UNNEEDED)
{ fprintf(stderr, "towire_onchain_unwatch_tx called!\n"); abort(); }
/* Generated stub for towire_u16 */
void towire_u16(u8 **pptr UNNEEDED, u16 v UNNEEDED)
{ fprintf(stderr, "towire_u16 called!\n"); abort(); }
/* Generated stub for towire_u8_array */
void towire_u8_array(u8 **pptr UNNEEDED, const u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_u8_array called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

/* Stubs which do get called. */
u8 *towire_hsm_sign_local_htlc_tx(const tal_t *ctx UNNEEDED, u64 commit_num UNNEEDED, const struct bitcoin_tx *tx UNNEEDED, const u8 *wscript UNNEEDED, struct amount_sat input_amount UNNEEDED)
{
	return NULL;
}

u8 *wire_sync_read(const tal_t *ctx UNNEEDED, int fd UNNEEDED)
{
	return (u8 *)ctx;
}

bool wire_sync_write(int fd UNNEEDED, const void *msg TAKES UNNEEDED)
{
	return true;
}

/* Generated stub for fromwire_hsm_sign_tx_reply */
bool fromwire_hsm_sign_tx_reply(const void *p UNNEEDED, struct bitcoin_signature *sig)
{
	memset(sig, 0, sizeof(*sig));
	return true;
}

void status_fmt(enum log_level level UNNEEDED,
		const struct node_id *node_id,
		const char *fmt UNNEEDED, ...)
{
}

static void signature_from_hex(const char *hex, struct bitcoin_signature *sig)
{
	u8 der[74];
	size_t len = hex_data_size(strlen(hex));

	sig->sighash_type = SIGHASH_ALL;
	assert(len < sizeof(der));
	if (!hex_decode(hex, strlen(hex), der, len))
		abort();

	if (!signature_from_der(der, len, sig))
		abort();
}

/* We don't have enough info to make this from first principles, but we have
 * an example tx, so just mangle that. */
struct bitcoin_tx *htlc_timeout_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   const struct bitcoin_txid *commit_txid UNNEEDED,
				   unsigned int commit_output_number UNNEEDED,
				   struct amount_msat htlc_msatoshi,
				   u32 cltv_expiry,
				   u16 to_self_delay UNNEEDED,
				   u32 feerate_per_kw UNNEEDED,
				   const struct keyset *keyset UNNEEDED)
{
	struct bitcoin_tx *tx;
	struct amount_sat in_amount;

	tx = bitcoin_tx_from_hex(ctx, "0200000001a02a38c6ec5541963704a2a035b3094b18d69cc25cc7419d75e02894618329720000000000000000000191ea3000000000002200208bfadb3554f41cc06f00de0ec2e2f91e36ee45b5006a1f606146784755356ba532f10800",
				 strlen("0200000001a02a38c6ec5541963704a2a035b3094b18d69cc25cc7419d75e02894618329720000000000000000000191ea3000000000002200208bfadb3554f41cc06f00de0ec2e2f91e36ee45b5006a1f606146784755356ba532f10800"));
	assert(tx);

	in_amount = amount_msat_to_sat_round_down(htlc_msatoshi);
	tx->input_amounts[0] = tal_dup(tx, struct amount_sat, &in_amount);
	tx->chainparams = chainparams;

	tx->wtx->locktime = cltv_expiry;
	return tx;
}

int main(void)
{
	struct bitcoin_signature remotesig;
	struct tracked_output *out;
	struct keyset *keys;
	size_t *matches;
	struct htlc_stub htlcs[3];
	u8 *htlc_scripts[3];

	setup_locale();
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);
	setup_tmpctx();
	chainparams = chainparams_for_network("bitcoin");

	htlcs[0].cltv_expiry = 585998;
	htlcs[1].cltv_expiry = 585998;
	htlcs[2].cltv_expiry = 586034;
	htlc_scripts[0] = tal_hexdata(tmpctx, "76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868",
				      strlen("76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868"));
	htlc_scripts[1] = tal_hexdata(tmpctx, "76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868",
				      strlen("76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868"));
	htlc_scripts[2] = tal_hexdata(tmpctx, "76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868",
				 strlen("76a914f454b1fe5b95428d6beec58ed3131a6ea611b2fa8763ac672103f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da67c820120876475527c21026ebaa1d08757b86110e40e3f4a081803eec694e23ec75ee0bfd753589df896e752ae67a9148dbcec4a5d782dd87588801607ea7dfc8874ffee88ac6868"));

	/* talz keeps valgrind happy. */
	out = talz(tmpctx, struct tracked_output);
	bitcoin_txid_from_hex("722983619428e0759d41c75cc29cd6184b09b335a0a20437964155ecc6382aa0", strlen("722983619428e0759d41c75cc29cd6184b09b335a0a20437964155ecc6382aa0"), &out->txid);
	out->outnum = 0;
	if (!parse_amount_sat(&out->sat, "3215967sat", strlen("3215967sat")))
		abort();
	signature_from_hex("3045022100917efdc8577e8578aef5e513fad25edbb55921466e8ffccb05ce8bb05a54ae6902205c2fded9d7bfc290920821bfc828720bc24287f3dad9a62fb4f806e2404ed0f401", &remotesig);
	out->remote_htlc_sig = tal_dup(out, struct bitcoin_signature, &remotesig);

	/* Make mapping 1:1 for this */
	matches = tal_arr(tmpctx, size_t, 3);
	matches[0] = 0;
	matches[1] = 1;
	matches[2] = 2;

	keyset = keys = tal(tmpctx, struct keyset);
	if (!pubkey_from_hexstr("03f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da6",
				strlen("03f83ca95b22920e71487736a7284696dd52443fd8f7ce683153ac31d1d1db7da6"),
				&keys->other_htlc_key))
		abort();

	min_possible_feerate = 10992;
	max_possible_feerate = 15370;

	size_t ret = resolve_our_htlc_ourcommit(chainparams_by_bip173("bc"),
						out,
						matches,
						htlcs,
						htlc_scripts,
						false);
	assert(ret == 2);
	take_cleanup();
	tal_free(tmpctx);
	secp256k1_context_destroy(secp256k1_ctx);
}
