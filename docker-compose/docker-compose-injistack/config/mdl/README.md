# Demo mDL holder data

Synthetic data for the mDL profile of `docs/design/20-mdl-issuer.md` (M-10). No real person is in here: the names say
"Demo"/"Test" and the portraits are generated silhouettes (decision D2).

| File | What it is |
| --- | --- |
| `holders.json` | Three mDL records keyed by subject id (`mdl-demo-1`..`mdl-demo-3`), each carrying the ISO/IEC 18013-5 Table 5 mandatory elements plus `sex`, `age_over_18`, `nationality` and `resident_city` |
| `portrait-1.jpg`..`portrait-3.jpg` | The portraits the records name: baseline JPEG, 160x200, a few kilobytes each |

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
become the template data map, and a missing claim or no matching record answers `400 invalid_credential_request`.
Fields in `binary-fields` name a path relative to the JSON file's directory; their bytes are read once at startup and
served as base64url without padding, the shape an mDoc `bstr` element such as `portrait` takes from the template.
Absolute paths and paths escaping the JSON directory are refused at startup, as are a missing file and malformed JSON.
With no `sources.<id>` entry the feature is off.
