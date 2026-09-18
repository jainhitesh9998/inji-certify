package io.mosip.certify.keyprovider.keymanager;

import io.mosip.certify.signing.KeyRequirement;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.SymmetricKeyGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Startup key provisioning, moved here from {@code AppConfig.initKeys}: keymanager's own master keys (ROOT,
 * CERTIFY_SERVICE with its cache secret, CERTIFY_PARTNER) always, then the VC signing keys when the service runs
 * in {@code DataProvider} plugin mode. The signing keys are the four aliases the service has always created plus
 * every alias named in {@code mosip.certify.signature-algo.key-alias-mapper}, so a deployment that maps an
 * algorithm to its own application id gets that key created too.
 */
public class KeymanagerKeyInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(KeymanagerKeyInitializer.class);

    // Mirrors io.mosip.certify.core.constants.Constants; kept local so this module does not depend on certify-core.
    static final String ROOT_KEY = "ROOT";
    static final String CERTIFY_SERVICE_APP_ID = "CERTIFY_SERVICE";
    static final String CERTIFY_PARTNER_APP_ID = "CERTIFY_PARTNER";
    static final String OBJECT_TYPE_CSR = "CSR";
    static final String PLUGIN_MODE_DATA_PROVIDER = "DataProvider";

    /** The signing keys every DataProvider deployment has had since 0.10: alias in {@link KeymanagerAlias} form. */
    static final List<KeyRequirement> LEGACY_SIGNING_KEYS = List.of(
            new KeyRequirement("CERTIFY_VC_SIGN_RSA", SignatureAlgorithm.RS256, KeymanagerKeyProvider.PURPOSE_VC_SIGNING),
            new KeyRequirement("CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", SignatureAlgorithm.EdDSA, KeymanagerKeyProvider.PURPOSE_VC_SIGNING),
            new KeyRequirement("CERTIFY_VC_SIGN_EC_K1/EC_SECP256K1_SIGN", SignatureAlgorithm.ES256K, KeymanagerKeyProvider.PURPOSE_VC_SIGNING),
            new KeyRequirement("CERTIFY_VC_SIGN_EC_R1/EC_SECP256R1_SIGN", SignatureAlgorithm.ES256, KeymanagerKeyProvider.PURPOSE_VC_SIGNING));

    private final KeymanagerService keymanagerService;
    private final KeymanagerKeyProvider keyProvider;
    private final String cacheSecretKeyRefId;
    private final String pluginMode;
    private final Map<String, List<List<String>>> keyAliasMapper;

    public KeymanagerKeyInitializer(KeymanagerService keymanagerService, KeymanagerKeyProvider keyProvider,
                                    String cacheSecretKeyRefId, String pluginMode, Map<String, List<List<String>>> keyAliasMapper) {
        this.keymanagerService = keymanagerService;
        this.keyProvider = keyProvider;
        this.cacheSecretKeyRefId = cacheSecretKeyRefId;
        this.pluginMode = pluginMode;
        this.keyAliasMapper = keyAliasMapper == null ? Map.of() : keyAliasMapper;
    }

    @Override
    public void run(ApplicationArguments args) {
        ensureMasterKeys();
        if (PLUGIN_MODE_DATA_PROVIDER.equals(pluginMode)) {
            List<KeyRequirement> required = signingKeyRequirements();
            log.info("===================== CERTIFY VC SIGNING KEY CHECK ({} keys) ========================", required.size());
            keyProvider.ensureKeys(required);
        }
        log.info("===================== CERTIFY KEY SETUP COMPLETED ========================");
        log.info("===================== INJI Certify -- Started ============================");
    }

    /** Keymanager's own hierarchy: the root, the service master key, its cache secret and the partner master key. */
    void ensureMasterKeys() {
        log.info("===================== CERTIFY_SERVICE ROOT KEY CHECK ========================");
        // keymanager expects an empty reference id for master keys
        keymanagerService.generateMasterKey(OBJECT_TYPE_CSR, KeymanagerKeyProvider.request(ROOT_KEY, ""));
        log.info("===================== CERTIFY_SERVICE MASTER KEY CHECK ========================");
        keymanagerService.generateMasterKey(OBJECT_TYPE_CSR, KeymanagerKeyProvider.request(CERTIFY_SERVICE_APP_ID, ""));
        if (cacheSecretKeyRefId != null && !cacheSecretKeyRefId.isBlank()) {
            SymmetricKeyGenerateRequestDto symmetricKey = new SymmetricKeyGenerateRequestDto();
            symmetricKey.setApplicationId(CERTIFY_SERVICE_APP_ID);
            symmetricKey.setReferenceId(cacheSecretKeyRefId);
            symmetricKey.setForce(false);
            keymanagerService.generateSymmetricKey(symmetricKey);
            log.info("============= CERTIFY_SERVICE CACHE SYMMETRIC KEY CHECK COMPLETED =============");
        }
        log.info("===================== CERTIFY_PARTNER MASTER KEY CHECK ========================");
        keymanagerService.generateMasterKey(OBJECT_TYPE_CSR, KeymanagerKeyProvider.request(CERTIFY_PARTNER_APP_ID, ""));
    }

    /** The legacy four in their historical order, then mapper entries not already covered. */
    List<KeyRequirement> signingKeyRequirements() {
        Set<String> seen = new LinkedHashSet<>();
        List<KeyRequirement> required = new ArrayList<>();
        for (KeyRequirement legacy : LEGACY_SIGNING_KEYS) {
            seen.add(legacy.alias());
            required.add(legacy);
        }
        keyAliasMapper.forEach((jose, aliases) -> {
            SignatureAlgorithm algorithm = SignatureAlgorithm.fromJose(jose).orElse(null);
            if (algorithm == null || !keyProvider.supportedAlgorithms().contains(algorithm)) {
                log.warn("key-alias-mapper names algorithm {} which kernel-keymanager cannot generate; skipping", jose);
                return;
            }
            for (List<String> pair : aliases) {
                KeymanagerAlias alias = new KeymanagerAlias(pair.get(0), pair.size() > 1 ? pair.get(1) : "");
                if (seen.add(alias.toString())) {
                    required.add(new KeyRequirement(alias.toString(), algorithm, KeymanagerKeyProvider.PURPOSE_VC_SIGNING));
                }
            }
        });
        return required;
    }

    static KeyPairGenerateRequestDto masterKeyRequest(String applicationId) {
        return KeymanagerKeyProvider.request(applicationId, "");
    }
}
