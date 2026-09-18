/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.credential;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;
import java.util.Map;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.signing.JwsEnvelope;
import io.mosip.certify.signing.JwsHeaderPolicy;
import io.mosip.certify.signing.KeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.LegacyKeyRefs;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.utils.SDJsonUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.SignatureService;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Component
public class SDJWT extends Credential{

    @Autowired
    public SDJWT(VCFormatter vcFormatter, SignatureService signatureService){
        super(vcFormatter, signatureService);
    }

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private KeyProviderRegistry keyProviders;

    /**
     * This method returns true when a format can be handled.
     */
    @Override
    public boolean canHandle(String format){
        return VCFormats.DC_SD_JWT.equals(format);
    }


        /**
         * createCredential method is resposible to convert the given template and
         * templateparams into the requested credential format. This not just a
         * template replacement but should also have all logics necessary to conver
         * this to a proper verifiable credential.Any additional VC level atributes
         * or context or etc should be handled by the inherrited class.
         * upon error it returns an empty JWT.
         * upon success it returns the unsiged sd-jwt with disclosure
         *
         * @param updatedTemplateParams The params map that would be used to replace the
         *                       template
         * @param templateName   The actual template
         */
    @Override
    public String createCredential(Map<String, Object> updatedTemplateParams, String templateName) {
        SDObjectBuilder sdObjectBuilder = new SDObjectBuilder();
        List<Disclosure> disclosures = new ArrayList<>();
        PlainHeader header = new PlainHeader();
        JsonNode node;
        String currentPath = "$";

        String templatedJSON = super.createCredential(updatedTemplateParams, templateName);
        List<String> sdPaths = super.vcFormatter.getSelectiveDisclosureInfo(templateName);   
        try {
            
            node = objectMapper.readTree(templatedJSON);
            for (String path : sdPaths) {
                if (!SDJsonUtils.isPathValid(node, path)) {
                    throw new CertifyException(ErrorConstants.SD_CLAIMS_PARSE_ERROR, "SD-Claim path '" + path + "' not found in the credential template.");
                }
            }
            SDJsonUtils.constructSDPayload(node, sdObjectBuilder, disclosures, sdPaths, currentPath);
            Map<String,Object>  sdClaims = sdObjectBuilder.build();
            JWTClaimsSet claimsSet = JWTClaimsSet.parse(sdClaims);
            PlainJWT jwt = new PlainJWT(header, claimsSet);
            com.authlete.sd.SDJWT sdJwt = new com.authlete.sd.SDJWT(jwt.serialize(), disclosures);
            return sdJwt.toString();
        } catch (JsonProcessingException ex) {
            log.error("JSON processing error", ex);
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR, "Failed to process JSON during SD-JWT creation.");
        }
        catch (ParseException ex) {
            log.error("Final SDClaims un parseable. Mostly a bug in the code and has to be reported ", ex);
            throw new CertifyException(ErrorConstants.SD_CLAIMS_PARSE_ERROR, "Failed to parse SD-Claims while creating SD-JWT.");
        }
    }

    /**
     * Adds a signature/proof. Based on the actual implementation the input 
     * could be different, its recommended that the input matches the output 
     * of the respective createCredential, for eg: Base64, Sringified JSON etc.
     * <p>In the defaulat abstract implementation we assume 
     * ```Base64.getUrlEncoder().encodeToString(vcToSign)``` </p>
     * @param vcToSign actual vc as returned by the `createCredential` method. 
     * @param headers headers to be added. Can be null.
     * @param signAlgorithm as defined in com.danubetech.keyformats.jose.JWSAlgorithm
     * @param appID app id from the keymanager tables
     * @param refID referemce id from the keymanager tables
     * @param didUrl url where the public key is accesible.
     */
    @Override
    public VCResult<?> addProof(String vcToSign, String headers, String signAlgorithm, String appID, String refID, String didUrl, String signatureCryptoSuite) {
        VCResult<String> vcResult = new VCResult<>();
        String[] jwt = vcToSign.split("~");
        String[] jwtPayload = jwt[0].split("\\.");
        KeyRef ref = LegacyKeyRefs.keymanager(appID, refID);
        KeyProvider provider = keyProviders.provider(ref.provider());
        SignatureAlgorithm algorithm = SignatureAlgorithm.fromJose(signAlgorithm)
                .orElseThrow(() -> new CertifyException(ErrorConstants.VC_SIGNING_ERROR, "Unsupported signature algorithm " + signAlgorithm));
        SigningKey key = provider.resolve(ref).withAlgorithm(algorithm);
        byte[] payloadBytes = Base64.getUrlDecoder().decode(jwtPayload.length > 1 ? jwtPayload[1] : jwtPayload[0]);
        // header: alg, typ dc+sd-jwt, kid, x5c, x5t#S256 (what keymanager's jwsSignV2 emitted for this request)
        String issuerJws = JwsEnvelope.sign(payloadBytes, JwsHeaderPolicy.sdJwtVc(), key, provider);
        vcResult.setCredential(vcToSign.replaceAll("^[^~]*", java.util.regex.Matcher.quoteReplacement(issuerJws)));
        return vcResult;
    }

}
