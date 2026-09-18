# Recording the draft-13 goldens from release 0.14.0

The files under `certify-service/src/test/resources/goldens/d13` were produced by `D13GoldenRecorder` running inside a
checkout of release 0.14.0 (`e54539a`), in process: the real service on H2 with the PKCS#12 keymanager, Velocity and
the `local` profile's TestBearer filter, driven through MockMvc with the same mock data and configurations as the v1
goldens (`IssuanceGoldenTest`). To re-record:

```bash
git worktree add /tmp/certify-0.14.0 e54539a
mkdir -p /tmp/certify-0.14.0/certify-service/src/test/java/io/mosip/certify/golden /tmp/certify-0.14.0/certify-service/src/test/resources/goldens/templates
cp certify-service/src/test/java/io/mosip/certify/golden/Goldens.java docs/design/wp/p0-02-recorder/D13GoldenRecorder.java /tmp/certify-0.14.0/certify-service/src/test/java/io/mosip/certify/golden/
cp docs/design/wp/p0-02-recorder/d13-schema-patch.sql /tmp/certify-0.14.0/certify-service/src/test/resources/
cp certify-service/src/test/resources/goldens/templates/golden-{ldp,sdjwt,mdoc}.vm /tmp/certify-0.14.0/certify-service/src/test/resources/goldens/templates/
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
(cd /tmp/certify-0.14.0 && mvn -B -ntp -s "$OLDPWD/.mvn/settings-local.xml" -Dmaven.legacyLocalRepo=true -Dgpg.skip=true -Dmaven.gitcommitid.skip=true -DskipTests -pl certify-core,certify-integration-api,certify-service -am install)
(cd /tmp/certify-0.14.0 && mvn -B -ntp -s "$OLDPWD/.mvn/settings-local.xml" -Dmaven.legacyLocalRepo=true -Dgpg.skip=true -Dmaven.gitcommitid.skip=true -pl certify-service test -Dtest=D13GoldenRecorder -Dsurefire.failIfNoSpecifiedTests=false)
rm -rf certify-service/src/test/resources/goldens/d13 && cp -R /tmp/certify-0.14.0/certify-service/src/test/resources/goldens/d13 certify-service/src/test/resources/goldens/d13
```

A second run of the recorder must report no recorded files (the set is stable). `d13-schema-patch.sql` replaces the
0.14.0 H2 `credential_config` table, whose test schema predates the entity of that release (missing
`signature_crypto_suite`, `mso_mdoc_claims`, `sd_jwt_claims`, `sd_jwt_vct`, `credential_status_purpose`, `qr_*`, and
a primary key on context and type that rejects SD-JWT and mDoc rows).
