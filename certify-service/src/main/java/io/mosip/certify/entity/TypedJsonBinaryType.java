package io.mosip.certify.entity;

import io.hypersistence.utils.hibernate.type.json.JsonBinaryType;
import io.hypersistence.utils.hibernate.type.util.JsonConfiguration;
import io.hypersistence.utils.hibernate.type.util.ObjectMapperWrapper;
import org.hibernate.type.spi.TypeBootstrapContext;
import org.hibernate.usertype.DynamicParameterizedType;

import java.io.Serializable;
import java.lang.reflect.Type;
import java.util.Properties;

/**
 * {@link JsonBinaryType} whose copies have the attribute's declared generic type, so Hibernate's dirty check compares
 * like with like.
 *
 * <p>Hibernate keeps a copy of every attribute of an entity it loads in a read-write session and, at flush, compares
 * the entity's value with that copy; any difference rewrites the whole row. For a {@code @Type(JsonBinaryType.class)}
 * attribute the copy is made by hypersistence-utils' {@code ObjectMapperJsonSerializer.clone}, which serialises the
 * value to JSON and reads it back as {@code LinkedHashMap<keyClass, valueClass>} taken from the first entry's runtime
 * classes. For {@code Map<String, Map<String, Claims>>} (the {@code mso_mdoc_claims} column) the value class is a raw
 * {@code LinkedHashMap}, so every {@code Claims} in the copy becomes a {@code LinkedHashMap}, {@code Claims.equals}
 * never matches it, and the attribute is dirty on every load: one {@code UPDATE credential_config} per mDoc row and
 * flush, on PostgreSQL as on H2 (F-17 review round 2, B1). The other JSON attributes of {@link CredentialConfig} copy
 * correctly ({@code Map<String, Claims>} carries {@code Claims} as the runtime value class; the lists of maps go through
 * Java serialisation), so only {@code msoMdocClaims} uses this type.
 *
 * <p>Every copy Hibernate takes through the user type is typed and independent of the value it came from:
 * <ul>
 *   <li>{@link #deepCopy} (the load snapshot and {@code merge}) writes the value with the same {@code ObjectMapper} the
 *       column uses and reads it back as the declared type - what a load produces;</li>
 *   <li>{@link #disassemble} (the second-level cache form) is that JSON text, immutable, so nothing the session does
 *       later reaches the cached copy; {@link #assemble} reads it back as the declared type, a new value each time.
 *       The inherited pair went through the same untyped clone and handed back {@code LinkedHashMap}s (review round
 *       3).</li>
 * </ul>
 * Hibernate 6.4 builds a {@code @Type} attribute's mutability plan from the user type itself
 * ({@code UserTypeMutabilityPlanAdapter}: {@code deepCopy}, {@code disassemble}, {@code assemble}; {@code replace} also
 * copies through {@code deepCopy}), which is why the fix is here rather than in an {@code @Mutability} annotation that a
 * {@code @Type} attribute ignores. Reads and writes of the column are untouched: binding, extraction and the
 * {@code ObjectMapper} ({@link JsonConfiguration#getObjectMapperWrapper()}, the one {@link JsonBinaryType} is built
 * with) are inherited, so the stored bytes are what {@link JsonBinaryType} has always written.
 *
 * <p>The declared type is the entity field's generic type, found by name from the {@code ENTITY} and {@code PROPERTY}
 * parameters Hibernate passes to every dynamic parameterized type, so this class needs no internal hypersistence or
 * Hibernate type.
 */
public class TypedJsonBinaryType extends JsonBinaryType {

    /**
     * The mapper this type copies with: the same one {@link JsonBinaryType} reads and writes with, so a deployment that
     * configures hypersistence's ObjectMapper through Hibernate settings gets one mapper for the column end to end.
     */
    private final ObjectMapperWrapper json;

    public TypedJsonBinaryType() {
        super();
        this.json = JsonConfiguration.INSTANCE.getObjectMapperWrapper();
    }

    public TypedJsonBinaryType(TypeBootstrapContext bootstrapContext) {
        super(bootstrapContext);
        this.json = new JsonConfiguration(bootstrapContext.getConfigurationSettings()).getObjectMapperWrapper();
    }

    /** The attribute's declared type, generics included ({@code Map<String, Map<String, Claims>>}). */
    private Type declaredType;

    @Override
    public void setParameterValues(Properties parameters) {
        super.setParameterValues(parameters);
        declaredType = declaredType(parameters.getProperty(DynamicParameterizedType.ENTITY),
                parameters.getProperty(DynamicParameterizedType.PROPERTY));
    }

    @Override
    public Object deepCopy(Object value) {
        return value == null ? null : json.fromString(json.toString(value), type());
    }

    @Override
    public Serializable disassemble(Object value) {
        return value == null ? null : json.toString(value);
    }

    @Override
    public Object assemble(Serializable cached, Object owner) {
        return cached == null ? null : json.fromString((String) cached, type());
    }

    private Type type() {
        if (declaredType == null) {
            throw new IllegalStateException("TypedJsonBinaryType was not given its attribute (ENTITY and PROPERTY parameters)");
        }
        return declaredType;
    }

    /** The generic type of {@code property} on {@code entity} or one of its superclasses. */
    static Type declaredType(String entity, String property) {
        if (entity == null || property == null) {
            throw new IllegalStateException("TypedJsonBinaryType needs the entity and property it maps, got " + entity + "." + property);
        }
        Class<?> type;
        try {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            type = Class.forName(entity, false, loader != null ? loader : TypedJsonBinaryType.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("TypedJsonBinaryType cannot load the entity " + entity, e);
        }
        for (Class<?> c = type; c != null; c = c.getSuperclass()) {
            try {
                return c.getDeclaredField(property).getGenericType();
            } catch (NoSuchFieldException ignored) {
                // declared on a superclass
            }
        }
        throw new IllegalStateException("TypedJsonBinaryType: no field " + property + " on " + entity);
    }
}
