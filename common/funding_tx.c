#include "funding_tx.h"
#include <assert.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <bitcoin/varint.h>
#include <ccan/ptrint/ptrint.h>
#include <common/permute_tx.h>
#include <common/type_to_string.h>
#include <common/utxo.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

struct bitcoin_tx *funding_tx(const tal_t *ctx,
			      u16 *outnum,
			      const struct utxo **utxomap,
			      struct amount_sat funding,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      struct amount_sat change,
			      const struct pubkey *changekey,
			      const struct ext_key *bip32_base)
{
	u8 *wscript;
	struct bitcoin_tx *tx;
	bool has_change = !amount_sat_eq(change, AMOUNT_SAT(0));

	tx = tx_spending_utxos(ctx, utxomap, bip32_base, has_change);


	wscript = bitcoin_redeem_2of2(tx, local_fundingkey, remote_fundingkey);
	SUPERVERBOSE("# funding witness script = %s\n",
		     tal_hex(wscript, wscript));
	bitcoin_tx_add_output(tx, scriptpubkey_p2wsh(tx, wscript), &funding);
	tal_free(wscript);

	if (has_change) {
		const void *map[2];
		map[0] = int2ptr(0);
		map[1] = int2ptr(1);
		bitcoin_tx_add_output(tx, scriptpubkey_p2wpkh(tx, changekey),
				      &change);
		permute_outputs(tx, NULL, map);
		*outnum = (map[0] == int2ptr(0) ? 0 : 1);
	} else {
		*outnum = 0;
	}

	permute_inputs(tx, (const void **)utxomap);
	assert(bitcoin_tx_check(tx));
	return tx;
}

#ifdef EXPERIMENTAL_FEATURES
/* We leave out the change addresses if there's no change left after fees */
static size_t calculate_input_weights(struct input_info **inputs,
				      struct amount_sat *total)
{
	u32 input_weight;
	u64 scriptlen;
	size_t weight = 0, i = 0;

	for (i = 0; i < tal_count(inputs); i++) {
		/* prev_out hash + index + sequence */
		input_weight = (32 + 4 + 4) * 4;

		if (inputs[i]->script) {
			scriptlen = tal_bytelen(inputs[i]->script);	
			input_weight += (scriptlen + varint_size(scriptlen)) * 4;
		} else {
			/* 00 byte script_sig len */
			input_weight += 1 * 4;
		}

		input_weight += inputs[i]->max_witness_len;
		weight += input_weight;

		assert(amount_sat_add(total, *total, inputs[i]->satoshis));
	}

	return weight;
}

static size_t calculate_output_weights(struct output_info **outputs)
{
	size_t i, output_weights = 0, scriptlen;

	for (i = 0; i < tal_count(outputs); i++) {
		scriptlen = tal_bytelen(outputs[i]->script);	
		/* amount field + script + scriptlen varint */
		output_weights += (8 + scriptlen + varint_size(scriptlen)) * 4;
	}

	return output_weights;
}

static size_t calculate_weight(struct input_info **opener_inputs,
		               struct input_info **accepter_inputs,
		               struct output_info **opener_outputs,
		               struct output_info **accepter_outputs,
			       struct amount_sat *opener_total,
			       struct amount_sat *accepter_total)

{
	size_t weight;

	/* version, input count, output count, locktime */
	weight = (4 + 1 + 1 + 4) * 4;

	/* add segwit fields: marker + flag */
	weight += 1 + 1;

	weight += calculate_input_weights(opener_inputs, opener_total);
	weight += calculate_input_weights(accepter_inputs, accepter_total);

	/* channel funding output: amount, len, scriptpubkey */
	weight += (8 + 1 + BITCOIN_SCRIPTPUBKEY_P2WSH_LEN) * 4;

	weight += calculate_output_weights(opener_outputs);
	weight += calculate_output_weights(accepter_outputs);

	return weight;
}

static const struct output_info *find_change_output(struct output_info **outputs)
{
	size_t i = 0;
	for (i = 0; i < tal_count(outputs); i++) {
		if (amount_sat_eq(outputs[i]->satoshis, AMOUNT_SAT(0)))
			return outputs[i];
	}
	return NULL;
}

static struct amount_sat calculate_output_value(struct output_info **outputs)
{
	size_t i = 0;
	struct amount_sat total = AMOUNT_SAT(0);

	for (i = 0; i < tal_count(outputs); i++) {
		assert(amount_sat_add(&total, total, outputs[i]->satoshis));
	}
	return total;
}

static void add_inputs(struct bitcoin_tx *tx, struct input_info **inputs)
{
	size_t i = 0;
	for (i = 0; i < tal_count(inputs); i++) {
		const struct bitcoin_txid prev_txid = {{ inputs[i]->prevtx_txid }};
		bitcoin_tx_add_input(tx, &prev_txid, inputs[i]->prevtx_vout,
				     BITCOIN_TX_DEFAULT_SEQUENCE,
				     &inputs[i]->satoshis, inputs[i]->script);
	}
}

static void add_outputs(struct bitcoin_tx *tx, struct output_info **outputs,
		        const struct amount_sat *change)
{
	size_t i = 0;
	u8 *script;
	struct amount_sat value;

	for (i = 0; i < tal_count(outputs); i++) {
		/* Is this the change output?? */
		if (change && amount_sat_eq(outputs[i]->satoshis, AMOUNT_SAT(0))) {
			if (amount_sat_eq(*change, AMOUNT_SAT(0)))
				continue;
			value = *change;	
		} else
			value = outputs[i]->satoshis;
			
		script = tal_dup_arr(tx, u8, outputs[i]->script, 
				     tal_count(outputs[i]->script), 0);
		bitcoin_tx_add_output(tx, script, &value);
	}
}

struct bitcoin_tx *dual_funding_funding_tx(const tal_t *ctx,
				           u16 *outnum,
					   u32 feerate_kw_funding,
					   struct amount_sat *total_funding,
				           struct amount_sat *opener_funding,
					   struct amount_sat accepter_funding,
				           struct input_info **opener_inputs,
				           struct input_info **accepter_inputs,
					   struct output_info **opener_outputs,
					   struct output_info **accepter_outputs,
				           const struct pubkey *local_fundingkey,
				           const struct pubkey *remote_fundingkey,
					   void ***input_map)
{
	size_t weight;	
	struct amount_sat funding_tx_fee, opener_total_sat,
			  accepter_total_sat,
			  opener_change, output_val;
	struct bitcoin_tx *tx;
	const struct output_info *change_output;

	size_t i = 0;
	u64 scriptlen;
	u32 input_count, output_count;
	u8 *wscript;

	/* First, we calculate the weight of the transaction, with change outputs */
	weight = calculate_weight(opener_inputs, accepter_inputs, opener_outputs, accepter_outputs,
				  &opener_total_sat, &accepter_total_sat);
	funding_tx_fee = amount_tx_fee(feerate_kw_funding, weight);

	if (!amount_sat_sub(&opener_change, opener_total_sat, *opener_funding))
		return NULL;

	if (amount_sat_sub(&opener_change, opener_change, funding_tx_fee)) {
		/* Check that there's a change output */
		if (!find_change_output(opener_outputs)) {
			/* This should definitely work because we just subtracted it out above */
			assert(amount_sat_add(opener_funding, *opener_funding, opener_change));
			opener_change = AMOUNT_SAT(0);
		}
		goto build_tx;
	}

	/* Try removing opener's change output */
	change_output = find_change_output(opener_outputs);
	if (change_output) {
		scriptlen = tal_count(change_output->script);
		weight -= (8 + scriptlen + varint_size(scriptlen)) * 4;
		funding_tx_fee = amount_tx_fee(feerate_kw_funding, weight);
		
		/* Recalculate the opener_change */
		assert(amount_sat_sub(&opener_change, opener_total_sat, *opener_funding));
		if (amount_sat_sub(&opener_change, opener_change, funding_tx_fee)) {
			assert(amount_sat_add(opener_funding, *opener_funding, opener_change));
			opener_change = AMOUNT_SAT(0);
			goto build_tx;
		}
}

	output_val = calculate_output_value(opener_outputs);
	if (!amount_sat_sub(opener_funding, opener_total_sat, funding_tx_fee) ||
		!amount_sat_sub(opener_funding, *opener_funding, output_val))
		return NULL;

	opener_change = AMOUNT_SAT(0);

build_tx:
	input_count = tal_count(opener_inputs) + tal_count(accepter_inputs);
	/* opener + accepter outputs plus the funding output */
	output_count = tal_count(opener_outputs) 
		+ tal_count(accepter_outputs) + 1;

	if (amount_sat_eq(AMOUNT_SAT(0), opener_change))
		output_count -= 1;

	tx = bitcoin_tx(ctx, input_count, output_count);

	/* Add the funding output */
	wscript = bitcoin_redeem_2of2(tx, local_fundingkey, remote_fundingkey);
	SUPERVERBOSE("# funding witness script = %s\n",
		     tal_hex(wscript, wscript));

	*total_funding = *opener_funding;
	assert(amount_sat_add(total_funding, *total_funding, accepter_funding));
	
	const void *map[output_count];
	for (i = 0; i < output_count; i++) {
		map[i] = int2ptr(i);
	}
	bitcoin_tx_add_output(tx, scriptpubkey_p2wsh(tx, wscript), total_funding);

	/* Add the other outputs */
	add_outputs(tx, opener_outputs, &opener_change);
	add_outputs(tx, accepter_outputs, NULL);

	permute_outputs(tx, NULL, map);

	for (i = 0; i < output_count; i++) {
		if (map[i] == int2ptr(0)) {
			*outnum = i;
			break;
		}
	}

	/* Note that hsmd depends on the opener's inputs
	 * being added before the accepter's inputs */
	add_inputs(tx, opener_inputs);
	add_inputs(tx, accepter_inputs);

	for (i = 0; i < input_count; i++) {
		map[i] = int2ptr(i);
	}
	permute_inputs(tx, map);
	if (input_map != NULL)
		*input_map = (void **)&map;

	assert(bitcoin_tx_check(tx));
	return tx;
}
#endif /* EXPERIMENTAL_FEATURES */
