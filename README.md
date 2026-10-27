# Tailscale SDK for Workshop

This SDK connects a workshop to a tailnet. The workshop joins as a
user-attributed device through the new Tailscale OAuth app device flow, so
everything on the tailnet, including SSH into hosts, internal HTTP and
database services, and MagicDNS names, is reachable from inside the
workshop container. Workshop devices carry identity attributes, so tailnet
policy can scope what each workshop node may reach.

---

## Reference workshop

A complete workshop definition:

```yaml
# workshop.yaml
name: my-workshop
base: ubuntu@26.04
sdks:
  - name: tailnet
    channel: latest/beta
  - name: system
    plugs:
      tailscale-auth:
        interface: tunnel
        endpoint: localhost:8765
    slots:
      tailscale-oauth-app:
        interface: secret
        collection: default
        attributes:
          service: tailscale.com/workshop/oauth-app
          app: Canonical-Workshop

actions:
  tailscale: tailscale "$@"
```

This installs the SDK from the store under its current name, `tailnet`, and
puts the Tailscale CLI on the workshop PATH. The `tailscale-auth` tunnel
plug on the `system` SDK forwards the host's port 8765 into the workshop,
where the SDK's matching slot exposes the OAuth callback endpoint, and the
`tailscale-oauth-app` secret slot supplies the OAuth app credential created
during setup; the `app` attribute must match the OAuth app name given to
`workshop-tailnet setup`, which defaults to `Canonical-Workshop`. The
credential is not connected automatically: connect it explicitly after
launching the workshop:

```bash
workshop connect my-workshop/tailnet:tailscale-oauth-app \
  my-workshop/system:tailscale-oauth-app
```

The remaining sections walk through each part of this example.

---

## Using the SDK

### Prerequisites

1. An OAuth app established in the tailnet, with its credential, the client
   ID and client secret, available to the desktop that runs Workshop.
   Two roles are involved:

   - The tailnet administrator establishes the app once, with
     `go tool workshop-tailnet setup` or manually through the Tailscale API.
     "Create the OAuth app" walks through both.
   - The administrator then distributes the credential to every user and
     host that runs a workshop. "Distribute the credential" covers storing
     it on each receiving desktop.
2. A desktop Secret Service for the OAuth app credential. On Ubuntu this is
   the GNOME keyring, accessed with `secret-tool` from the `libsecret-tools`
   package; the keyring may prompt for unlocking or access. Without a Secret
   Service the credential falls back to a private file, described under
   "Create the OAuth app".
3. A browser on the desktop that runs Workshop. The authorisation callback is
   forwarded from the desktop into the workshop through the `tailscale-auth`
   tunnel.
4. No project layout is required. The SDK provides tailnet connectivity, not a
   build toolchain.

On launch, the SDK puts the `tailscale` CLI on the workshop PATH and enables
the `tailscaled` daemon. A workshop node that is not yet logged in starts the
authentication service, which prints the authorisation URL in shells attached
to a terminal, including the shell that `workshop shell` opens. On refresh,
the node's state is preserved and the workshop is not re-authorised.

### Create the OAuth app

A tailnet administrator establishes the OAuth app once, for the whole tailnet.
The client ID and client secret that it yields are not specific to any one
workshop: they are distributed to every user and host that runs a workshop in
the tailnet, and each stores the same credential on the desktop that starts
its workshops. Getting going is therefore first an administrator problem,
then a distribution problem.

#### As a tailnet administrator

Check out this repository. The Go tooling is already configured, so no
compilation step is needed; run the helper from the repository root:

```bash
go tool workshop-tailnet setup
```

The helper registers a Tailscale OAuth app in your tailnet and stores its
credential on your desktop, ready for distribution. It prompts for:

1. A Tailscale Owner or Admin API access token, used for this setup only and
   never saved.
2. An app name, defaulting to `Canonical-Workshop`. The name identifies the
   credential later, in the secret slot's `app` attribute.
3. A redirect URI, defaulting to `http://127.0.0.1:8765/callback`. This must
   match the endpoint of the `tailscale-auth` tunnel plug in the workshop
   definition.

The helper shows a confirmation summary before creating the app, listing the
name, redirect URI, scope, and the node attributes the app allows. The
credential stores the SDK format: `client_id`, `client_secret`, `name`,
`redirect_uris`, `scopes`, and `allowed_node_attributes`. After storing it,
the helper prints the `system` slot fragment from the reference workshop
above, with the `app` attribute filled in, and the `workshop connect`
command.

If the desktop Secret Service is unavailable, the credential falls back to a
private file, `$XDG_CONFIG_HOME/workshop-tailnet/oauth-app.json` (or
`~/.config/workshop-tailnet/oauth-app.json` when unset), with mode `0600` in a
directory with mode `0700`. If both storage methods fail, the helper prints
the one-time client credentials for manual recovery; treat that output as
sensitive.

Related commands, also run from the repository root with `go tool`:
`go tool workshop-tailnet list-oauth-apps` lists the OAuth apps in your
tailnet, and `go tool workshop-tailnet remove-oauth-app <client-id>` removes
one by client ID.

#### Manually, with the Tailscale API

The OAuth app is a standard Tailscale OAuth app used for device
provisioning. Follow the app creation steps in the Tailscale API
documentation:

- [Device provisioning with OAuth apps](https://tailscale.com/docs/features/oauth-apps/device-provisioning)
- [Tailscale API](https://tailscale.com/docs/reference/tailscale-api)

In broad terms, with the SDK's defaults filled in:

```bash
curl -X POST https://api.tailscale.com/api/v2/tailnet/-/oauth-apps \
  -H "Authorization: Bearer $TS_API_TOKEN" \
  --data-binary @- <<'JSON'
{
  "name": "Canonical-Workshop",
  "redirectUris": ["http://127.0.0.1:8765/callback"],
  "scopes": ["auth_keys:create:once"],
  "allowedNodeAttributes": [
    "custom:canonicalWorkshopIs",
    "custom:canonicalWorkshopName",
    "custom:canonicalWorkshopProjectId"
  ]
}
JSON
```

The response includes the client ID and client secret; Tailscale shows the
client secret only once. Store the credential in the SDK format
(`client_id`, `client_secret`, `name`, `redirect_uris`, `scopes`, and
`allowed_node_attributes`) as described above, with the `app` attribute set
to the name you chose, `Canonical-Workshop` in this example.

#### Distribute the credential

Each user and host that runs a workshop needs the same credential JSON on the
desktop that starts its workshops. Share it from the administrator desktop
through your organisation's usual secure channel; export it from the Secret
Service with the same attributes:

```bash
secret-tool lookup \
  service tailscale.com/workshop/oauth-app app Canonical-Workshop
```

On the receiving desktop, store it with the attributes the SDK looks it up
by:

```bash
secret-tool store --label='Canonical-Workshop OAuth app' \
  --collection=default -- \
  service tailscale.com/workshop/oauth-app app Canonical-Workshop
```

Paste the credential JSON on the command's standard input. The workshop
definition's `app` attribute must match the name the app was created with.

### Wire the credential and callback into your workshop

With the credential on the desktop, three pieces from the reference workshop
connect it to a workshop:

1. The `tailscale-oauth-app` secret slot on the `system` SDK entry. Its
   `attributes` must match the credential's lookup attributes:
   `service: tailscale.com/workshop/oauth-app`, and `app` set to the app
   name, `Canonical-Workshop` by default.
2. The `tailscale-auth` tunnel plug on the `system` SDK entry, forwarding
   the desktop's port 8765 into the workshop. It pairs with the SDK's own
   `tailscale-auth` slot by matching name, so it connects automatically and
   needs no `connections:` entry. The redirect URI recorded in the
   credential must match this endpoint.
3. The `tailscale-oauth-app` secret plug declared by this SDK, which consumes
   the credential. Secret connections are never automatic, so connect it
   explicitly after launching the workshop:

```bash
workshop launch
workshop connect my-workshop/tailnet:tailscale-oauth-app \
  my-workshop/system:tailscale-oauth-app
```

No restart is needed: the in-workshop authentication service retries until
the connected credential is available, then starts the authorisation flow
covered in the next section. Verify the wiring with
`workshop connections`, which lists the tunnel connection as automatic and
the secret connection as manual.

### Authenticate the workshop node

The daemon decides from its own login state whether authentication is
needed, so an already-provisioned node never asks again. On a fresh launch,
open a shell:

```bash
workshop shell
```

If the node is not yet logged in, the shell prints the authorisation URL:

```
Tailscale authentication is required.
Open this URL in your browser:
  https://login.tailscale.com/a/oauth_authorize?...
```

Open that URL in the desktop browser and approve the request. The browser
redirects to the app's redirect URI on the desktop, `localhost:8765`; the
`tunnel` connection forwards it into the workshop, where the SDK provisions
the node with a one-time auth key and `tailscale up` connects the tailnet.
The key is consumed immediately and never shown.

Back in the shell, the workshop node is now a device in the tailnet. Verify
from inside the workshop:

```bash
tailscale status
tailscale ping <host>
```

A node whose key expired server-side re-enters the authentication flow by
itself: the next shell prints a fresh URL, and the same approval provisions
it again. Consent is requested again as well when a workshop that was
stopped is started, since the node was deregistered on shutdown.

### Node identity and posture

Every provisioned workshop device is stamped with three custom node
attributes, sent during the OAuth token exchange:

| Attribute | Value |
|---|---|
| `custom:canonicalWorkshopIs` | always `true` |
| `custom:canonicalWorkshopName` | the workshop hostname, with dashes replaced by underscores |
| `custom:canonicalWorkshopProjectId` | the project ID from `/project/.workshop.lock`, omitted outside a workshop |

The names use camelCase because the Tailscale API only allows letters,
numbers, and underscores in attribute names, and only letters, numbers,
underscores, and periods in string values, which is why the name value uses
underscores.

Reference the attributes in tailnet device posture conditions and grants,
including by value, to scope what each workshop node may reach. For example,
a grant that allows SSH to servers only from workshops in one project:

```json
{
  "grants": [
    {
      "src": ["custom:canonicalWorkshopIs=true",
               "custom:canonicalWorkshopProjectId=MY_PROJECT"],
      "dst": ["tag:server"],
      "ip":  ["tcp:22"]
    }
  ]
}
```

The attributes also identify workshop devices for external cleanup tooling,
for example removing nodes left behind by containers that were killed
without a graceful shutdown.

### Lifecycle: refresh, stop, and removal

The Tailscale node state lives in the workshop container's filesystem,
which a refresh rebuilds. The SDK preserves it:

- On **refresh**, the node state is saved to the SDK state directory before
  the rebuild and merged back into the new container before the daemon
  first runs. The daemon resumes from its own login state, so a
  provisioned workshop is never re-authorised and makes no authorisation
  requests when refreshed. Its identity, addresses, and tailnet
  registration are unchanged.
- On **stop** and **remove**, the container shuts down and the daemon
  deregisters the node from the tailnet. The two are indistinguishable
  inside the container, so both deregister, and a later start re-runs the
  authentication flow and asks for consent again.
- A **crash** or a kill without a graceful shutdown keeps the registration:
  the daemon never ran its stop hook. The node stays in the tailnet until
  its key expires; identify stale nodes by the `custom:canonicalWorkshop*`
  attributes and clean them up with the admin console or API.

---

## Plugs (resources this SDK consumes)

### `tailscale-oauth-app`

- Interface: `secret`
- Target: the OAuth app credential created during setup
- Purpose: Supplies the Tailscale OAuth app credential that provisions the
  workshop node. The credential uses the SDK format described under
  "Create the OAuth app": `client_id`, `client_secret`, `name`,
  `redirect_uris`, `scopes`, and `allowed_node_attributes`.
- The matching slot is declared on the `system` SDK entry with the
  attributes the credential is stored under, as shown in the reference
  workshop.
- This plug is **not** connected automatically. Connect it explicitly after
  launching the workshop:

  ```bash
  workshop connect my-workshop/tailnet:tailscale-oauth-app \
    my-workshop/system:tailscale-oauth-app
  ```

## Slots (resources this SDK provides)

### `tailscale-auth`

- Interface: `tunnel`
- Endpoint: `127.0.0.1:8765`
- Purpose: Exposes the OAuth callback endpoint inside the workshop. The
  desktop declares a matching tunnel plug on the `system` SDK entry,
  forwarding its port 8765 in, and the browser's redirect completes the
  authentication flow in the workshop.
- The connection pairs automatically when the plug and slot names match and
  the endpoints are loopback; no `connections:` entry is needed.

---

## Documentation and guidance

- [Tailscale documentation](https://tailscale.com/docs)
- [Device provisioning with OAuth apps](https://tailscale.com/docs/features/oauth-apps/device-provisioning)
- [Tailscale API](https://tailscale.com/docs/reference/tailscale-api)
- [Workshop documentation](https://ubuntu.com/workshop/docs/)

---

## Community and support

- Tailscale community: [Tailscale Discussions](https://github.com/tailscale/tailscale/discussions)
- Workshop forum:
  [Discourse](https://discourse.ubuntu.com/)
- Please review our
  [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct) before
  participating.

---

## Contributions

All contributions, including code, documentation updates, and issue reports,
are welcome!

- Open issues or pull requests on the official repository.

---

## License and copyright

Copyright 2026 Canonical Ltd.

This program is free software: you can redistribute it and/or modify it under
the terms of the
[GNU Lesser General Public License version 2.1 (LGPLv2.1)](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

[Tailscale](https://github.com/tailscale/tailscale) is licensed under the
[BSD 3-Clause License](https://github.com/tailscale/tailscale/blob/v1.104.2/LICENSE).
