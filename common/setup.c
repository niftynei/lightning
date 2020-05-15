#include <ccan/ccan/err/err.h>
#include <common/memleak.h>
#include <common/setup.h>
#include <common/utils.h>
#include <sodium.h>
#include <wally_core.h>

static const tal_t *wally_tal_ctx;

static void *wally_tal(size_t size)
{
	return tal_arr_label(wally_tal_ctx, u8, size, "wally_notleak");
}

static void wally_free(void *ptr)
{
	tal_free(ptr);
}

static struct wally_operations wally_tal_ops = {
	.malloc_fn = wally_tal,
	.free_fn = wally_free,
};


void common_setup(const char *argv0)
{
	setup_locale();
	err_set_progname(argv0);

	/* We rely on libsodium for some of the crypto stuff, so we'd better
	 * not start if it cannot do its job correctly. */
	if (sodium_init() == -1)
		errx(1, "Could not initialize libsodium. Maybe not enough entropy"
		     " available ?");

	/* We set up Wally, the bitcoin wallet lib */
	wally_tal_ctx = tal_label(NULL, char, "wally_ctx_notleak");
	wally_init(0);
	wally_set_operations(&wally_tal_ops);
	secp256k1_ctx = wally_get_secp_context();

	setup_tmpctx();
}

void common_shutdown(void)
{
	tal_free(tmpctx);
	wally_cleanup(0);
	tal_free(wally_tal_ctx);
}
