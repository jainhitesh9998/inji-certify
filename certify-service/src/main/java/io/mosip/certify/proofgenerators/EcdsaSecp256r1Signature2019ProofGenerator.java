package io.mosip.certify.proofgenerators;

import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.LdLegacyEnvelope;
import io.mosip.certify.signing.LegacyKeyRefs;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Map;

/** EC_SECP256R1_2019: signs the URDNA2015 hash through the key provider the configuration's key columns name (P1-03). */
@Component
public class EcdsaSecp256r1Signature2019ProofGenerator implements ProofGenerator {

    @Autowired
    KeyProviderRegistry keyProviders;

    Canonicalizer canonicalizer = new URDNA2015Canonicalizer();

    @Override
    public String getName() {
        return SignatureAlg.EC_SECP256R1_2019;
    }

    @Override
    public Canonicalizer getCanonicalizer() {
        return canonicalizer;
    }

    @Override
    public LdProof generateProof(LdProof vcLdProof, String vcEncodedHash, Map<String, String> keyID) {
        KeyRef ref = LegacyKeyRefs.keymanager(keyID.get(Constants.APPLICATION_ID), keyID.get(Constants.REFERENCE_ID));
        KeyProvider provider = keyProviders.provider(ref.provider());
        SigningKey key = provider.resolve(ref).withAlgorithm(SignatureAlgorithm.ES256);
        byte[] hash = Base64.getUrlDecoder().decode(vcEncodedHash);
        String proofValue = LdLegacyEnvelope.proofValueBase58(hash, key, provider);
        return LdProof.builder().base(vcLdProof).defaultContexts(false).proofValue(proofValue).build();
    }
}
