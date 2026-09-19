package io.mosip.certify.utils;

import io.ipfs.multibase.Multibase;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCFormats;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Template lookup keys and the render-method digest shared by the legacy issuance path and the new-surface listeners. */
public final class CredentialUtils {

    private CredentialUtils() {
    }

    /**
     * The key a legacy template is stored under: {@code format::vct} for SD-JWT, {@code format::doctype} for mDoc,
     * otherwise the sorted types, the sorted contexts and the format joined by {@code ::}.
     */
    public static String getTemplateName(VCRequestDto vcRequestDto) {
        if (vcRequestDto.getFormat().equals(VCFormats.DC_SD_JWT)) {
            return String.join(Constants.DELIMITER, vcRequestDto.getFormat(), vcRequestDto.getVct());
        }
        if (vcRequestDto.getFormat().equals(VCFormats.MSO_MDOC)) {
            return String.join(Constants.DELIMITER, vcRequestDto.getFormat(), vcRequestDto.getDoctype());
        }
        List<String> contexts = new ArrayList<>(vcRequestDto.getContext());
        List<String> types = new ArrayList<>(vcRequestDto.getType());
        Collections.sort(contexts);
        Collections.sort(types);
        return String.join(Constants.DELIMITER, String.join(",", types), String.join(",", contexts), vcRequestDto.getFormat());
    }

    /**
     * The {@code digestMultibase} of an SVG rendering template (https://w3c-ccg.github.io/vc-render-method/#svgrenderingtemplate):
     * a base58btc multibase ({@code z}) of the SHA-256 of the SVG.
     */
    public static String getDigestMultibase(String svg) {
        try {
            byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(svg.getBytes(StandardCharsets.UTF_8));
            return Multibase.encode(Multibase.Base.Base58BTC, sha256);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
