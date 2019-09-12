/* Unit that burns utxos when their time comes */

#include <bitcoin/script.h>
#include <ccan/cast/cast.h>
#include <common/key_derive.h>
#include <common/wallet_tx.h>
#include <common/withdraw_tx.h>
#include <errno.h>
#include <hsmd/gen_hsm_wire.h>
#include <lightningd/chaintopology.h>
#include <lightningd/lightningd.h>
#include <wallet/burn_unit.h>
#include <wire/wire_sync.h>

struct sweep_tx {
	struct wallet *w;
	struct wallet_tx *wtx;
	struct bitcoin_tx *tx;
};

static void burn_tx_broadcast(struct bitcoind *bitcoind UNUSED,
			      int exitstatus, const char *msg,
			      struct sweep_tx *stx)
{
	struct amount_sat to_us;
	struct bitcoin_txid txid;

	if (exitstatus != 0) {
		log_unusual(stx->w->log,
			    "Unable to publish burn transaction. Errno %d "
			    "tx: %s", exitstatus,
			    type_to_string(stx, struct bitcoin_tx, stx->tx));

		tal_free(stx);
		return;
	}

	/* Add tx to our database! */
	bitcoin_txid(stx->tx, &txid);
	wallet_transaction_add(stx->w, stx->tx, 0, 0);

	/* Should we use a different type here? */
	wallet_transaction_annotate(stx->w, &txid, TX_CHANNEL_SWEEP, 0);

	/* Mark used outputs as spent */
	wallet_confirm_utxos(stx->w, stx->wtx->utxos);

	/* Extract the change output and add it to the DB */
	wallet_extract_owned_outputs(stx->w, stx->tx, NULL, &to_us);

	// FIXME: cancel the channels. how do we find
	// associated canais?
	tal_free(stx);
	return;

}

void burn_transactions(struct wallet *w, u32 tip_height)
{
	struct bitcoin_tx *signed_tx;
	struct bitcoin_txid txid, signed_txid;
	struct bitcoin_tx_output **outputs, *change_output;
	struct bitcoin_tx_input **inputs;
	struct pubkey *changekey;
	struct sweep_tx *stx;
	struct wallet_tx *wtx;
	u32 feerate_per_kw;

	stx = tal(NULL, struct sweep_tx);
	wtx = tal(stx, struct wallet_tx);
	stx->wtx = wtx;
	stx->w = w;

	/* There are no '3rd party' inputs */
	inputs = tal_arr(stx, struct bitcoin_tx_input *, 0);

	wtx_init(NULL, wtx, AMOUNT_SAT(-1ULL));
	wtx->all_funds = true;

	outputs = tal_arr(wtx, struct bitcoin_tx_output *, 0);

	feerate_per_kw = try_get_feerate(w->ld->topology, FEERATE_NORMAL);

	wtx->utxos = wallet_get_burnable_utxos(stx, w, tip_height);

	if (!tal_count(wtx->utxos)) {
		log_info(w->ld->log, "No burnable outputs found at "
			 "blockheight %d", tip_height);
		tal_free(stx);
		return;
	} else
		log_info(w->ld->log, "Found %ld burnable output%s at "
			 "blockheight %d. Initiating spend.",
			 tal_count(wtx->utxos),
			 tal_count(wtx->utxos) > 1 ? "s" : "",
			 tip_height);

       if (wtx_from_utxos(wtx, get_chainparams(w->ld),
			  feerate_per_kw, 0, tip_height, wtx->utxos)) {
               log_broken(w->ld->log, "Unable to create tx for burnable utxos."
		          " Aborting burn at attempt at height %d", tip_height);
	       return;
       }

	/* Add 'change' output for total value */
	assert(amount_sat_eq(wtx->change, AMOUNT_SAT(0)));
	changekey = tal(wtx, struct pubkey);
	if (!bip32_pubkey(w->bip32_base, changekey, wtx->change_key_index))
		fatal("Changekey generation failure");

	change_output = new_tx_output(outputs, wtx->amount,
				      (const u8 *)scriptpubkey_p2wpkh(tmpctx, changekey));
	tal_arr_expand(&outputs, change_output);

	stx->tx = withdraw_tx(wtx, get_chainparams(w->ld),
			      wtx->utxos, NULL, outputs,
			      w->bip32_base, NULL);

	/* FIXME: hsm will sign almost anything, but it should really
	 * fail cleanly (not abort!) and let us report the error here. */
	u8 *msg = towire_hsm_sign_withdrawal(stx,
					     cast_const2(const struct bitcoin_tx_input **,
							 inputs),
					     cast_const2(const struct bitcoin_tx_output **,
							 outputs),
					     wtx->utxos);

	if (!wire_sync_write(w->ld->hsm_fd, take(msg)))
		fatal("Could not write sign_withdrawal to HSM: %s",
		      strerror(errno));

	msg = wire_sync_read(tmpctx, w->ld->hsm_fd);

	if (!fromwire_hsm_sign_withdrawal_reply(tmpctx, msg, &signed_tx))
		fatal("HSM gave bad sign_withdrawal_reply %s",
		      tal_hex(tmpctx, msg));
	signed_tx->chainparams = stx->tx->chainparams;

	/* Sanity check */
	bitcoin_txid(stx->tx, &txid);
	bitcoin_txid(signed_tx, &signed_txid);
	if (!bitcoin_txid_eq(&signed_txid, &txid))
		fatal("HSM changed txid: unsigned %s, signed %s",
		      tal_hex(tmpctx, linearize_tx(tmpctx, stx->tx)),
		      tal_hex(tmpctx, linearize_tx(tmpctx, signed_tx)));

	/* Replace unsigned tx by signed tx. */
	tal_free(stx->tx);
	stx->tx = tal_steal(stx, signed_tx);

	log_debug(w->ld->log, "Sending burn tx %s to chain",
		  type_to_string(tmpctx, struct bitcoin_txid, &txid));

	/* Now broadcast the transaction */
	bitcoind_sendrawtx(w->ld->topology->bitcoind,
			   tal_hex(tmpctx, linearize_tx(tmpctx, stx->tx)),
			   burn_tx_broadcast, stx);
}
