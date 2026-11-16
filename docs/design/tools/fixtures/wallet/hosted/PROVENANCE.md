# Hosted verifier request objects (one-time manual capture, owner decision 2026-11-16)

Captured once by hand by the coordinator; tests only read these files and never contact the verifiers.

| File | Verifier | How | Captured (UTC; a request object's is its own `iat`) |
|---|---|---|---|
| eudi-request-get.jwt | verifier-backend.eudiw.dev | POST /ui/presentations/v2 (intended_use_id TEST-01, request_uri_method get, DCQL mso_mdoc mDL family_name/given_name/birth_date, nonce capture-p503c-20261116), then GET request_uri with Accept application/oauth-authz-req+jwt | 2026-11-16T05:30:33Z |
| eudi-request-post.jwt | verifier-backend.eudiw.dev | same, request_uri_method post; POST request_uri with wallet_nonce=capture-wallet-nonce-20261116 (echoed in the request object) | 2026-11-16T05:30:35Z |
| eudi-init-get.json, eudi-init-post.json | verifier-backend.eudiw.dev | the transaction init answers (client_id, request_uri, authorization_request_uri) | each just before the request object it led to: 05:30:33Z (get), 05:30:35Z (post) |
| mp-request.jwt | verifier.multipaz.org | POST /verifier/openid4vpBegin (protocol uri_scheme_openid4vp_29, scheme haip-vp://, signRequest, encryptResponse, raw DCQL mso_mdoc mDL family_name/given_name), then GET request_uri | 2026-11-16T05:31:09Z |
| mp-begin-response.json | verifier.multipaz.org | the begin answer (its uri; note the scheme form haip-vp://://?) | 2026-11-16T05:31:09Z |

Leaf certificates (the property the synthetic fixtures missed):
- EUDI: serial 606F16D48D021AC3A3E68F2E44F636AE3B786699 (20 bytes), CN=Web Verifier (PROD), issuer CN=PID Issuer CA 02, SAN URI:https://verifier.eudiw.dev only, valid 2026-08-14 .. 2028-08-13; client_id x509_hash.
- Multipaz: serial 0CDDC57CEE96CA929BD70EE9AB (13 bytes), CN=Verifier at https://verifier.multipaz.org, issuer C=US CN=verifier.multipaz.org Reader CA, SAN DNS:verifier.multipaz.org, valid 2026-08-10 .. 2027-02-06; client_id x509_san_dns:verifier.multipaz.org.

Tests evaluate them under a faked clock at the capture time (the request iat and the leaf validity), never the real now.
