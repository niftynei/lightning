#include "config.h"
#include <ccan/array_size/array_size.h>
#include <plugins/libplugin.h>

static struct command_result *
handle_invoice_payment(struct command *cmd,
		       const char *buf,
		       const jsmntok_t *params)
{
	plugin_log(cmd->plugin, LOG_INFORM,
		    "INVOICE PAYMENT INFO! '%.*s'",
		    json_tok_full_len(params),
		    json_tok_full(buf, params));

	return command_hook_success(cmd);
}

static const struct plugin_hook hooks[] = {
	{
		"invoice_payment",
		handle_invoice_payment
	},
};

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	return NULL;
}

int main(int argc, char *argv[])
{
	setup_locale();

	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL,
		    NULL, 0, // commands
		    NULL, 0, // notifications
		    hooks, ARRAY_SIZE(hooks), // hooks
		    NULL, 0, // notif topics?
		    NULL);
}
