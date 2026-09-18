package io.mosip.certify.configv2;

/** A refused v2 configuration call: HTTP status plus a stable error code, answered as {@code {error, error_description}}. */
public class ConfigV2Exception extends RuntimeException {

    public static final String INVALID_CONFIGURATION = "invalid_configuration";
    public static final String UNSUPPORTED_FORMAT = "unsupported_format";
    public static final String UNSUPPORTED_SIGNATURE_ALGORITHM = "unsupported_signature_algorithm";
    public static final String UNKNOWN_TEMPLATE_ENGINE = "unknown_template_engine";
    public static final String CONFIGURATION_EXISTS = "configuration_exists";
    public static final String CONFIGURATION_NOT_FOUND = "configuration_not_found";
    public static final String TEMPLATE_RENDER_FAILED = "template_render_failed";

    private final int status;
    private final String code;

    public ConfigV2Exception(int status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }

    public static ConfigV2Exception invalid(String message) {
        return new ConfigV2Exception(400, INVALID_CONFIGURATION, message);
    }
}
