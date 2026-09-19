/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.credential;

import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.signer.LdSigner;
import com.danubetech.dataintegrity.signer.LdSignerRegistry;
import com.danubetech.dataintegrity.suites.DataIntegrityProofDataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import io.mosip.certify.config.contextloader.StaticContextLoader;
import io.mosip.certify.core.constants.*;
import io.mosip.certify.core.dto.CertificateResponseDTO;
import io.mosip.certify.proofgenerators.ProofGeneratorFactory;
import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.LegacyKeyRefs;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SignerByteSigner;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.services.CertifyIssuanceServiceImpl;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.certify.vcformatters.VCFormatter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.apicatalog.jsonld.lang.Keywords;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.LdProof;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.proofgenerators.ProofGenerator;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Component
public class W3CJsonLD extends Credential{
    @Autowired
    ProofGeneratorFactory proofGeneratorFactory;
    @Autowired
    DIDDocumentUtil didDocumentUtil;

    @Value("#{${mosip.certify.signature-algo.key-alias-mapper}}")
    private Map<String, List<List<String>>> keyAliasMapper;

    @Autowired
    private StaticContextLoader staticContextLoader;



    /**
     * Constructor for credentials
     *
     * @param vcFormatter
     * @param signatureService
     */
    public W3CJsonLD(VCFormatter vcFormatter) {
        super(vcFormatter);
    }


    @Override
    public boolean canHandle(String format){
        if(format.equals(VCFormats.LDP_VC)){
            return true;
        }
        return false;
    }

    /**
     * Adds a signature/proof. Based on the actual implementation the input
     * could be different, its recommended that the input matches the output
     * of the respective createCredential, for eg: Base64, Sringified JSON etc.
     * <p>In the defaulat abstract implementation we assume
     * ```Base64.getUrlEncoder().encodeToString(vcToSign)``` </p>
     * @param vcToSign actual vc as returned by the `createCredential` method.
     * @param headers headers to be added. Can be null.
     */
    @Override
    public VCResult<?> addProof(String vcToSign, String signAlgorithm, String appID, String refID, String didUrl, String signatureCryptoSuite){
        VCResult<JsonLDObject> vcResult = new VCResult<>();
        Map<String,String> keyReferenceDetails = Map.of(Constants.APPLICATION_ID, appID, Constants.REFERENCE_ID, refID);
        JsonLDObject jsonLDObject = JsonLDObject.fromJson(vcToSign);
        jsonLDObject.setDocumentLoader(staticContextLoader);
        // NOTE: other aspects can be configured via keyMgrInput map
        String validFrom;
        if (jsonLDObject.getJsonObject().containsKey(VCDM1Constants.ISSUANCE_DATE)) {
            validFrom = jsonLDObject.getJsonObject().get(VCDM1Constants.ISSUANCE_DATE).toString();
        } else if (jsonLDObject.getJsonObject().containsKey(VCDM2Constants.VALID_FROM)){
            validFrom = jsonLDObject.getJsonObject().get(VCDM2Constants.VALID_FROM).toString();
        } else {
            validFrom = ZonedDateTime.now(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
        }
        // TODO: VC Data Model spec doesn't specify a single date format or a
        //  timezone restriction, this will have to be supported timely.
        Date createDate = Date
                .from(LocalDateTime
                        .parse(validFrom,
                                DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN))
                        .atZone(ZoneId.systemDefault()).toInstant());

        CertificateResponseDTO certificateResponseDTO = didDocumentUtil.getCertificateDataResponseDto(appID, refID);
        String kid = certificateResponseDTO.getKeyId();
        DataIntegrityProofDataIntegritySuite dataIntegrityProofDataIntegritySuite = DataIntegritySuites.DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF;
        List<String> supportedCryptoSuites = dataIntegrityProofDataIntegritySuite.findCryptosuitesForJwsAlgorithm(signAlgorithm);
        if (supportedCryptoSuites == null || !supportedCryptoSuites.contains(signatureCryptoSuite)) {
            // legacy signature algos such as Ed25519Signature{2018,2020}
            ProofGenerator proofGenerator = proofGeneratorFactory.getProofGenerator(signatureCryptoSuite)
                    .orElseThrow(() ->
                            new CertifyException("Proof generator not found for algorithm: " + signatureCryptoSuite));
            LdProof vcLdProof = LdProof.builder().defaultContexts(false).defaultTypes(false).type(proofGenerator.getName())
                    .created(createDate).proofPurpose(VCDMConstants.ASSERTION_METHOD)
                    .verificationMethod(URI.create(didUrl + "#" + kid))
                    .build();
            LdProof ldProofWithJWS = generateLdProof(vcLdProof, jsonLDObject,
                    keyReferenceDetails, proofGenerator);
            ldProofWithJWS.addToJsonLDObject(jsonLDObject);
        } else {
            LdSigner signer = LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(SignatureAlg.DATA_INTEGRITY);
            KeyRef ref = LegacyKeyRefs.keymanager(appID, refID);
            KeyProvider provider = keyProviders.provider(ref.provider());
            SignatureAlgorithm algorithm = SignatureAlgorithm.fromJose(signAlgorithm)
                    .orElseThrow(() -> new CertifyException("Unsupported signature algorithm " + signAlgorithm));
            SigningKey key = provider.resolve(ref).withAlgorithm(algorithm);
            signer.setSigner(new SignerByteSigner(provider, key, algorithm));
            signer.setCryptosuite(signatureCryptoSuite);

            DataIntegrityProof dataIntegrityProof = DataIntegrityProof.builder()
                    .created(createDate)
                    .proofPurpose(VCDMConstants.ASSERTION_METHOD)
                    .cryptosuite(signatureCryptoSuite)
                    .verificationMethod(URI.create(didUrl + "#" + kid))
                    .type(SignatureAlg.DATA_INTEGRITY).build();

            dataIntegrityProof = generateDataIntegrityProof(dataIntegrityProof, jsonLDObject, signer);
            dataIntegrityProof.addToJsonLDObject(jsonLDObject);
        }
        vcResult.setCredential(jsonLDObject);
        vcResult.setFormat(VCFormats.LDP_VC);
        return vcResult;
    }


    /** Legacy suites (Ed25519Signature2018/2020, RsaSignature2018, ...): canonicalise, then let the proof generator sign the hash. */
    private static LdProof generateLdProof(LdProof vcLdProof, JsonLDObject jsonLDObject, Map<String, String> keyReferenceDetails,
                                           ProofGenerator proofGenerator) {
        Canonicalizer canonicalizer = proofGenerator.getCanonicalizer();
        byte[] vcHashBytes;
        try {
            vcHashBytes = canonicalizer.canonicalize(vcLdProof, jsonLDObject);
        } catch (IOException | GeneralSecurityException | JsonLDException e) {
            log.error("Error occurred during canonicalization.", e);
            throw new CertifyException(ErrorConstants.CANONICALIZATION_ERROR, "Error occurred during canonicalization.");
        }
        String vcEncodedHash = Base64.getUrlEncoder().encodeToString(vcHashBytes);
        return proofGenerator.generateProof(vcLdProof, vcEncodedHash, keyReferenceDetails);
    }

    /** Data Integrity cryptosuites (eddsa-rdfc-2022, ecdsa-jcs-2019, ...): the danubetech signer canonicalises and signs. */
    private static DataIntegrityProof generateDataIntegrityProof(DataIntegrityProof dataIntegrityProof, JsonLDObject jsonLDObject, LdSigner signer) {
        DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder = DataIntegrityProof.builder()
                .base(dataIntegrityProof)
                .defaultContexts(false);
        try {
            signer.initialize(ldProofBuilder);
        } catch (GeneralSecurityException e) {
            log.error("Error during cryptosuite initialization", e);
            throw new CertifyException(ErrorConstants.CRYPTOSUITE_INITIALIZATION_ERROR, "Error occurred during crypto suite initialization.");
        }
        DataIntegrityProof ldProofOptions = DataIntegrityProof.fromJson(dataIntegrityProof.toJson());
        if (ldProofOptions.getContexts() == null || ldProofOptions.getContexts().isEmpty()) {
            JsonLDUtils.jsonLdAdd(ldProofOptions, Keywords.CONTEXT, jsonLDObject.getContexts().stream().map(JsonLDUtils::uriToString).filter(Objects::nonNull).toList());
        }
        com.danubetech.dataintegrity.canonicalizer.Canonicalizer canonicalizer = signer.getCanonicalizer(ldProofOptions);
        byte[] canonicalizationResult;
        try {
            canonicalizationResult = canonicalizer.canonicalize(ldProofOptions, jsonLDObject);
        } catch (IOException | GeneralSecurityException | JsonLDException e) {
            log.error("Error occurred during canonicalization.", e);
            throw new CertifyException(ErrorConstants.CANONICALIZATION_ERROR, "Error occurred during canonicalization.");
        }
        try {
            signer.sign(ldProofBuilder, canonicalizationResult);
        } catch (GeneralSecurityException e) {
            log.error("Error occurred while signing the Verifiable Credential.", e);
            throw new CertifyException(ErrorConstants.VC_SIGNING_ERROR, "Error occurred while signing the Verifiable Credential.");
        }
        return ldProofBuilder.build();
    }
}