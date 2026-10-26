# Workshop tailnet setup

Run `workshop-tailnet setup` on the desktop that supplies Workshop secrets.
The helper creates a Tailscale OAuth app and tries to save its credential
JSON in the desktop Secret Service's default collection using `secret-tool`
(from `libsecret-tools` on Ubuntu). A working desktop session and Secret
Service are required; the keyring may prompt for unlocking or access.

The secret contains the existing SDK credential format, unchanged:
`client_id`, `client_secret`, `name`, `redirect_uris`, and `scopes`.
The admin API token is never stored.

Lookup attributes are fixed:

- `service`: `tailscale.com/workshop/oauth-app`
- `app`: the OAuth app name

These attributes are public metadata, not secret contents. Attribute
customisation is not supported. An existing matching secret prevents app
creation; choose a different app name or manage the old entry first.
`secret-tool` lookup searches across collections, so even a match outside
of the default collection is treated as a collision. Avoid simultaneous
setup runs with the same app name; lookup and storage are not atomic.

After successful secret storage, the helper prints a slot fragment to merge
into the `system` SDK entry in your workshop definition, plus an explicit
`workshop connect` command. Replace `WORKSHOP` in that command with your
workshop name. Secret connections are not automatically granted.
The existing Tailscale secret plug and runtime credential format do not
need to change.

Inside the workshop, `tailscale-auth.service` is a system unit running as
`workshop`. The system manager retrieves the credential from Workshop's
restricted socket before starting the unprivileged helper. A user unit
cannot access that socket. SDK refresh removes the previous user unit.
The authentication service retries until a connected secret is available;
its URL is printed when you next enter an interactive login shell.

If lookup or storage fails, including when `secret-tool` is missing, the
helper reports the fallback and saves a private file instead. On Linux,
this is `$XDG_CONFIG_HOME/workshop-tailnet/oauth-app.json`, or
`~/.config/workshop-tailnet/oauth-app.json` when unset. The file uses mode
`0600` and its containing directory uses mode `0700`. Existing files are
not knowingly overwritten. File fallback does not create a Secret Service
entry or print a usable secret-slot configuration.

If both storage methods fail, setup prints the one-time client credentials
for manual recovery. Treat that output as sensitive. If a keyring write
failed or timed out, check the keyring before retrying: the service may have
accepted the write even though the helper did not observe success.

`remove-oauth-app` still removes the remote app and any matching fallback
file. It does not remove Secret Service entries yet; remove stale entries
using your desktop keyring manager before reusing the same app name.
