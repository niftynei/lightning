#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_H

#include "config.h"
#include <bitcoin/block.h>
#include <bitcoin/short_channel_id.h>
#include <bitcoin/tx.h>
#include <ccan/list/list.h>
#include <plugins/libplugin.h>
#include <wire/wire.h>

/* Forward declare hash table types (defined in bwatch_store.h) */
struct scriptpubkey_watches;
struct outpoint_watches;
struct scid_watches;
struct blockdepth_watches;

/* One owner/script pair supplied to a batched historical script scan. */
struct rescan_script {
	const char *owner;
	const u8 *scriptpubkey;
};

/* Select a logical wallet/watch set without exposing unrelated owners to
 * replay notifications.  Exactly one selector form is populated. */
struct rescan_selector {
	const char *owner_prefix;
	const char **owners;
};

/* Timer handle returned by global_timer; defined in libplugin. */
struct plugin_timer;

/* Wire-format block record stored in lightningd's datastore.
 * Defined by bwatch_wiregen.h; forward-declared here to avoid pulling
 * the generated header into every consumer of bwatch.h. */
struct block_record_wire;

/* Watch type discriminator. */
enum watch_type {
	WATCH_SCRIPTPUBKEY,
	WATCH_OUTPOINT,
	WATCH_SCID,
	WATCH_BLOCKDEPTH,
};

/* One ordered match collected by the transient wallet scanner.  Unlike the
 * normal watch_found path this is returned to the RPC caller, allowing it to
 * commit a historical wallet import synchronously and without racing plugin
 * notifications. */
struct rescan_match {
	enum watch_type type;
	const char *owner;
	u32 blockheight;
	u32 timestamp;
	u32 index;
	u8 *tx;
};

/* Scriptpubkey wrapper: tal-allocated bytes don't carry a length, so we
 * keep them in a struct with an explicit length for hashing/equality. */
struct scriptpubkey {
	const u8 *script;
	size_t len;
};

/* A single watch: one key plus the set of owner ids that registered it. */
struct watch {
	enum watch_type type;
	u32 start_block;
	wirestring **owners;
	union {
		struct scriptpubkey scriptpubkey;
		struct bitcoin_outpoint outpoint;
		struct short_channel_id scid;
	} key;
};

/* Main bwatch state.
 *
 * The four watch hash tables are typed (see bwatch_store.h) so each
 * lookup hits the right key shape (script bytes / outpoint / scid /
 * confirm-height) without dispatching on type at every call site. */
struct bwatch {
	struct plugin *plugin;
	u32 current_height;
	u32 backend_height;
	bool backend_height_known;
	struct bitcoin_blkid current_blockhash;
	/* Oldest first, most recent last. Used to replay a reorg by
	 * peeling tips off until the parent hash matches the new chain. */
	struct block_record_wire *block_history;

	struct scriptpubkey_watches *scriptpubkey_watches;
	struct outpoint_watches *outpoint_watches;
	struct scid_watches *scid_watches;
	struct blockdepth_watches *blockdepth_watches;

	/* Active poll timer; rescheduled at the end of every poll cycle. */
	struct plugin_timer *poll_timer;
	u32 poll_interval_ms;

	/* Opt-in: bwatch is loaded but stays inert (no chain polling, no
	 * watch processing) unless the user passes --experimental-bwatch. */
	bool experimental;

	/* Polling and historical rescans are independent, so a healthy tip poll
	 * must not hide an incomplete descriptor rescan. */
	char *last_poll_error;
	u32 last_poll_error_height;
	char *last_rescan_error;
	u32 last_rescan_error_height;
	u32 last_rescan_target_height;
	/* Monotonic process-lifetime counters make completed historical work
	 * observable even after its active cursor has disappeared. */
	u64 rescans_completed_total;
	u64 rescan_blocks_processed_total;

	/* Historical rescans can overlap when multiple add-watch RPCs are in
	 * flight.  Keep each cursor visible to bwatch-status. */
	struct list_head active_rescans;
};

/* Helper: get last block_history (or NULL) */
const struct block_record_wire *bwatch_last_block(const struct bwatch *bwatch);

/* Helper: retrieve the bwatch state from a plugin handle. */
struct bwatch *bwatch_of(struct plugin *plugin);

/* Timer callback: kicks off one chain-poll cycle (getchaininfo →
 * getrawblockbyheight → persist → reschedule).  Exposed so other modules
 * can schedule a poll from their own callbacks. */
struct command_result *bwatch_poll_chain(struct command *cmd, void *unused);

/* Pop the current tip from in-memory + persisted history.  Exposed so the
 * startup chaininfo path can roll back when bitcoind's chain is shorter
 * than what we have stored. */
void bwatch_remove_tip(struct command *cmd, struct bwatch *bwatch);

/* Per-rescan cursor: which block we're on and how far to go. */
struct rescan_state {
	struct list_node list;
	struct bwatch *bwatch;
	const struct watch *watch;	/* NULL = rescan all watches, non-NULL = single watch */
	/* A filtered snapshot of every watch type selected by owner. */
	struct bwatch *watch_set;
	const char *selector;
	/* Non-NULL for a batched script-only rescan.  Entries are snapshots
	 * containing only the owners named by the batch request. */
	struct scriptpubkey_watches *scriptpubkey_watches;
	/* scanwatchset uses a transient script table and grows its transient
	 * outpoint table as matching outputs are found. */
	bool collect_matches;
	struct rescan_match *matches;
	u64 script_matches_found;
	u64 outpoint_matches_found;
	u64 outpoints_followed;
	size_t watch_count;
	u32 start_block;		/* First block in the inclusive range */
	u32 current_block;		/* Next block to fetch */
	u32 target_block;		/* Stop after this block */
};

/* Replay historical blocks for `w` (or all watches if w==NULL) from
 * `start_block` up to `target_block` inclusive.  Runs asynchronously:
 * fetch -> process -> fetch the next block. */
void bwatch_start_rescan(struct command *cmd,
			 const struct watch *w,
			 u32 start_block,
			 u32 target_block);

/* Replay one historical range once for a set of script watches. */
void bwatch_start_scriptpubkey_rescan(struct command *cmd,
				      const struct rescan_script *scripts,
				      u32 start_block,
				      u32 target_block);

/* Scan transient scripts once, following every matching output forward as an
 * outpoint in the same pass.  Results are returned in block/transaction order
 * instead of being broadcast as notifications. */
void bwatch_start_wallet_scan(struct command *cmd,
			       const struct rescan_script *scripts,
			       u32 start_block,
			       u32 target_block);

/* Replay one historical range against only the owners selected here.  Returns
 * false without starting when the selector currently matches no watches. */
bool bwatch_start_watch_set_rescan(struct command *cmd,
				   const struct rescan_selector *selector,
				   u32 start_block,
				   u32 target_block);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_H */
