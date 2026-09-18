/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.credential;

import java.util.HashMap;
import java.util.Map;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.service.SignatureService;
import com.upokecenter.cbor.CBORObject;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.signing.CoseHeaderPolicy;
import io.mosip.certify.signing.CwtEnvelope;
import io.mosip.certify.signing.CwtSigningProperties;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.LegacyKeyRefs;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;
import org.springframework.beans.factory.annotation.Autowired;


@Slf4j
public abstract class Credential{
    
    protected VCFormatter vcFormatter;

    protected SignatureService signatureService;

    @Autowired
    private KeyProviderRegistry keyProviders;

    @Autowired
    private CwtSigningProperties cwtSigning;

    /**
     * Constructor for credentials
     * @param vcFormatter
     * @param signatureService
     */
    public Credential(VCFormatter vcFormatter, SignatureService signatureService){
        this.vcFormatter = vcFormatter;
        this.signatureService = signatureService;
    }

    /**
     * lets the factory know if the instance can handle the given format or not.
     * @param format
     * @return
     */
    public abstract boolean canHandle(String format);


    /**
     * createCredential method is resposible to convert the given template and
     * templateparams into the requested credential format. This not just a
     * template replacement but should also have all logics necessary to conver
     * this to a proper verifiable credential.Any additional VC level atributes
     * or context or etc should be handled by the inherrited class.
     *
     * @param updatedTemplateParams The params map that would be used to replace the
     *                       template
     * @param templateName   The actual template
     */
    public String createCredential(Map<String, Object> updatedTemplateParams, String templateName) {

        updatedTemplateParams.put(Constants.TEMPLATE_NAME, templateName);
        return vcFormatter.format(updatedTemplateParams);
    }

    /**
     * Creates the QR data(JSON Array) based on the final template and template name
     * @param updatedTemplateParams The params map that would be used to replace the
     *                       template
     * @param templateName   The actual template
     * @return JSON Array representing the QR data
     */
    public JSONArray createQRData(Map<String, Object> updatedTemplateParams, String templateName) {
        updatedTemplateParams.put(Constants.TEMPLATE_NAME, templateName);
        return vcFormatter.formatQRData(updatedTemplateParams);
    }

    /**
     * Creates a signature/proof and based on the actual implementation the input 
     * could be different, for eg: Base64, Sringified JSON etc.
     * <p>In the defaulat abstract implementation we assume 
     * ```Base64.getUrlEncoder().encodeToString(vcInBytes)``` </p>
     * @param vcToSign actual vc bytes 
     * @param headers headers to be added. Can be null.
     * @param signAlgorithm Signature algorithm RS256, PS256, ES256, etc
     * @param appID application id as per the keymanager table
     * @param refID reference id as per the keyamanger table
     * @param didUrl URL/URI of the public key
     */
    public VCResult<?> addProof(String vcToSign, String headers, String signAlgorithm, String appID, String refID, String didUrl, String signatureCryptoSuite) {

        JWSSignatureRequestDto payload = new JWSSignatureRequestDto();
        payload.setDataToSign(vcToSign);
        payload.setApplicationId(appID);
        payload.setReferenceId(refID); 
        payload.setIncludePayload(false);
        payload.setIncludeCertificate(false);
        payload.setIncludeCertHash(true);
        payload.setValidateJson(false);
        payload.setB64JWSHeaderParam(false);
        payload.setCertificateUrl(didUrl);
        payload.setSignAlgorithm(signAlgorithm); // RSSignature2018 --> RS256, PS256, ES256
        JWTSignatureResponseDto jwsSignedData = signatureService.jwsSign(payload);
        VCResult<String> vc = new VCResult<>();
        //TODO: Get the correct default
        vc.setFormat("vc");
        vc.setCredential(jwsSignedData.getJwtSignedData());
        return vc;
    }

    /*
    * Signs the QR data payload using CWT signature
    * @param payload The QR data payload to be signed
    * @param qrSignAlgorithm The QR signing algorithm
    * @param appID Application ID for key retrieval
    * @param refID Reference ID for key retrieval
    * @param didUrl DID URL of the issuer
    */
    public String signQRData(String payload, String qrSignAlgorithm, String appID, String refID, String didUrl) {
        KeyRef ref = LegacyKeyRefs.keymanager(appID, refID);
        KeyProvider provider = keyProviders.provider(ref.provider());
        SignatureAlgorithm algorithm = SignatureAlgorithm.fromJose(qrSignAlgorithm)
                .orElseThrow(() -> new CertifyException(ErrorConstants.VC_SIGNING_ERROR, "Unsupported QR signature algorithm " + qrSignAlgorithm));
        SigningKey key = provider.resolve(ref).withAlgorithm(algorithm);
        // Registered claims in the order keymanager wrote them (iss, exp, nbf, iat), then claim 169 as bstr .cbor
        Instant now = Instant.now();
        Map<Integer, Object> claims = new LinkedHashMap<>();
        claims.put(1, didUrl);
        claims.put(4, now.plus(Duration.ofDays(cwtSigning.expDays())).getEpochSecond());
        claims.put(5, now.plus(Duration.ofDays(cwtSigning.nbfDays())).getEpochSecond());
        claims.put(6, now.getEpochSecond());
        claims.put(169, claim169(payload));
        byte[] cwt = CwtEnvelope.sign(claims, CoseHeaderPolicy.cwt(), key, provider, true);
        log.info("CWT signed for claim 169");
        return HexFormat.of().formatHex(cwt);
    }

    /**
     * Claim 169 is {@code bstr .cbor}: PixelPass hands over the mapped data as CBOR hex (what keymanager wrapped as the
     * byte string); a JSON object is accepted too and encoded as a CBOR map with integer labels where the key is numeric.
     */
    static byte[] claim169(String mappedData) {
        if (mappedData.matches("(?:[0-9a-fA-F]{2})+")) {
            return HexFormat.of().parseHex(mappedData);
        }
        CBORObject json;
        try {
            json = CBORObject.FromJSONString(mappedData);
        } catch (RuntimeException e) {
            throw new CertifyException(ErrorConstants.VC_SIGNING_ERROR, "claim 169 payload is neither CBOR hex nor a JSON object: " + e.getMessage());
        }
        CBORObject map = CBORObject.NewMap();
        for (CBORObject k : json.getKeys()) {
            String name = k.AsString();
            CBORObject label = name.matches("-?\\d+") ? CBORObject.FromObject(Long.parseLong(name)) : k;
            map.Add(label, json.get(k));
        }
        return map.EncodeToBytes();
    }

}
