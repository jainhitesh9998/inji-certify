# Demo mDL holder data

Synthetic data for the mDL profile of `docs/design/20-mdl-issuer.md` (M-10). No real person is in here: the names say
"Demo"/"Test" and the portraits are generated silhouettes (decision D2).

| File | What it is |
| --- | --- |
| `holders.json` | Three mDL records keyed by subject id (`mdl-demo-1`..`mdl-demo-3`), each carrying the ISO/IEC 18013-5 Table 5 mandatory elements plus `sex`, `age_over_18`, `nationality` and `resident_city` |
| `portrait-1.jpg`..`portrait-3.jpg` | The portraits the records name: baseline JPEG, 160x200, a few kilobytes each |

`vehicle_category_code` values are the ISO/IEC 18013-1 codes (`AM`, `A1`, `A2`, `A`, `B1`, `B`, `BE`, `C1`, `C1E`, `C`,
`CE`, `D1`, `D1E`, `D`, `DE`), never a national marketing abbreviation such as `LMV` or `MCWG`.

Regenerate the portraits with `java docs/design/tools/generate_mdl_portraits.java docker-compose/docker-compose-injistack/config/mdl`.

## How Certify reads it

`FileCredentialDataSource` (`certify-service`, `io.mosip.certify.datasource.file`) serves one JSON file per source:

```properties
certify.datasource.file.sources.mdl-demo.path=<path>/holders.json
certify.datasource.file.sources.mdl-demo.key-claim=sub
certify.datasource.file.sources.mdl-demo.binary-fields=portrait
```

The file is a single JSON object whose keys are the values of `key-claim`; a credential configuration selects the
source with `dataSourceId: mdl-demo`. The claim is read from the validated access token, the matching record's fields
become the template data map (deeply immutable), and a missing claim or no matching record answers
`400 credential_request_denied` (OpenID4VCI 1.0 section 8.3.1.2; the draft-13 surface answers
`invalid_credential_request`). Fields in `binary-fields` name a path relative to the JSON file's directory; their bytes
are read once at startup and served as base64url without padding, the shape an mDoc `bstr` element such as `portrait`
takes from the template. Absolute paths and paths escaping the JSON directory (checked after resolving symlinks, so a
Kubernetes ConfigMap's `..data/` links are fine) are refused at startup, as are a missing or non-regular file,
malformed JSON (a duplicate record key and trailing content included), a JSON file above 5 MiB, a binary file above
1 MiB and more than 50 MiB read in total for one source. With no `sources.<id>` entry the feature is off.

Ids with a `-` (`mdl-demo`) work in properties and YAML files. They cannot be expressed as environment variables:
`CERTIFY_DATASOURCE_FILE_SOURCES_MDL_DEMO_PATH` binds the id `mdl.demo`, not `mdl-demo`, so an environment-only
deployment should use a dash-free id. The id `data-provider-plugin` is reserved for the plugin and refused.

## Trust: who this source believes

The record is chosen by the `sub` claim of the access token, so the source trusts the authorization server that issued
the token to name the holder. It authenticates nobody itself. On the public demo host (decision D12) the offer page and
`/pre-authorized-data` are public, so anyone who can mint an offer for `mdl-demo-1` receives that synthetic holder's
mDL. That is acceptable **only** because this data is synthetic. With real data, `/pre-authorized-data` must not be
public, or the authorization server must authenticate the holder before it issues the token whose `sub` lands here.

### The directory is trusted too

Containment is checked before the read: a field's path is resolved, compared with the JSON file's directory, and only
then read. These are two steps, so the directory is trusted to be writable **only by the deployment** that configures
the source. A writer that can replace a link or a file between the check and the read can make the read follow a path
that was not checked, and a hard link gives a file outside the directory a name inside it that passes the check. Both
are out of scope: closing them needs a descriptor-relative open (`openat` with `O_NOFOLLOW`), not a path check. Mount
the directory read-only, from a volume only the deployment writes.
