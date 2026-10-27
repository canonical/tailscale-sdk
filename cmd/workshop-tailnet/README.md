# Workshop tailnet setup

Run `workshop-tailnet setup` on the desktop that supplies Workshop secrets.
The helper creates a Tailscale OAuth app and tries to save its credential
JSON in the desktop Secret Service's default collection using `secret-tool`
(from `libsecret-tools` on Ubuntu). A working desktop session and Secret
Service are required; the keyring may prompt for unlocking or access.

The secret contains the SDK credential format:
`client_id`, `client_secret`, `name`, `redirect_uris`, `scopes`,
and `allowed_node_attributes`.
The admin API token is never stored.

Setup allowlists a fixed set of node attributes on the OAuth app, in a
Kubernetes-style namespace, and records them in the credential. The
confirmation summary shows the exact set. Attribute names are stored
without their `custom:` prefix; setup adds the prefix when registering
the app.

During authentication, the helper supplies each attribute's value in the
token exchange, so every workshop device is stamped with:

- `custom:canonicalWorkshopIs`: `true`
- `custom:canonicalWorkshopName`: the workshop hostname, with dashes
  replaced by underscores
- `custom:canonicalWorkshopProjectId`: the project ID from
  `/project/.workshop.lock`, omitted outside a workshop

The Tailscale API only allows letters, numbers, and underscores in
attribute names, and letters, numbers, underscores, and periods in
string values, which is why the namespace and the name value use
underscores.

Reference the attributes in tailnet device posture conditions and grants,
including by value, to restrict what workshop devices may reach and to
identify them for external cleanup tooling. Credentials whose attribute
set differs are rejected; re-run `workshop-tailnet setup` to register a
current app.

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
The existing Tailscale secret plug and runtime credential format stay
compatible; the credential gains the `allowed_node_attributes` field.

Inside the workshop, `tailscale-auth.service` is a system unit running as
`workshop`. The system manager retrieves the credential from Workshop's
restricted socket before starting the unprivileged helper. A user unit
cannot access that socket. SDK refresh removes the previous user unit.
The authentication service retries until a connected secret is available;
its URL is printed when a login shell attached to a terminal starts,
including the shell that "workshop shell" opens.

A workshop refresh rebuilds the container, which discards the Tailscale
node state in `/var/lib/tailscale`. The `save-state` and `restore-state`
hooks preserve it in the SDK state directory across the refresh,
re-entering the pre-refresh state: only the `provisioned` marker that
`tailscale-up.service` touches on success counts, so a refresh during
provisioning falls back to the normal authentication flow, while a
provisioned node's restore brings `tailscaled` up from the saved state
directly.

The base setup hook installs and enables the authentication service
but leaves starting it to the `check-health` hook, which runs after
state restoration and starts the OAuth flow only when no provisioned
marker exists. A provisioned workshop is therefore never re-authorised
and makes no authorisation requests when refreshed.

The `tailscaled` unit deregisters the node when the container shuts
down: workshop stop and workshop remove are indistinguishable inside
the container, so both are treated as removal, and starting a stopped
workshop re-runs the authentication flow and asks for consent again.
Refreshes are unaffected, because `save-state` stops the daemon before
the teardown shutdown; manual daemon stops and crashes keep the node
too. Containers killed without a graceful shutdown cannot deregister;
identify their nodes by the `canonicalWorkshop*` attributes.

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
