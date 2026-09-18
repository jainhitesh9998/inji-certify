package io.mosip.certify.template.velocity;

import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.tools.generic.DateTool;
import org.apache.velocity.tools.generic.EscapeTool;

import java.io.StringWriter;
import java.util.Map;

/**
 * The Velocity evaluation certify-service has always used: UTF-8 in and out, {@code _dateTool} and {@code _esc}
 * available to every template. Shared by the legacy {@code VCFormatter} and the SPI {@link VelocityTemplateEngine},
 * so both render byte-identically.
 */
public class VelocityRenderer {

    public static final String DATE_TOOL = "_dateTool";
    public static final String ESCAPE_TOOL = "_esc";

    private final VelocityEngine engine;

    public VelocityRenderer() {
        engine = new VelocityEngine();
        engine.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8");
        engine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        engine.init();
    }

    /** Evaluates the template text against the parameters; the tools are added when the caller has not. */
    public String evaluate(String template, Map<String, Object> parameters, String logTag) {
        parameters.putIfAbsent(DATE_TOOL, new DateTool());
        parameters.putIfAbsent(ESCAPE_TOOL, new EscapeTool());
        StringWriter writer = new StringWriter();
        engine.evaluate(new VelocityContext(parameters), writer, logTag, template);
        return writer.toString();
    }
}
