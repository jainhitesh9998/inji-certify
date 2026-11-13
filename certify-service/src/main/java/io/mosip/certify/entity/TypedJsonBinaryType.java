package io.mosip.certify.entity;

import io.hypersistence.utils.hibernate.type.json.JsonBinaryType;
import io.hypersistence.utils.hibernate.type.json.internal.JsonJavaTypeDescriptor;

/**
 * {@link JsonBinaryType} whose snapshot copy has the attribute's declared generic type, so Hibernate's dirty check
 * compares like with like.
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
 * <p>The copy here is what a load produces: the same {@code ObjectMapper} writes the value and reads it back as the
 * attribute's full generic type ({@link JsonJavaTypeDescriptor#fromString} uses the property type Hibernate passed in
 * {@code setParameterValues}). Reads and writes of the column are untouched: binding, extraction and the
 * {@code ObjectMapper} are inherited, so the stored bytes are what {@link JsonBinaryType} has always written.
 * Hibernate 6.4 builds a {@code @Type} attribute's mutability plan from the user type itself
 * ({@code UserTypeMutabilityPlanAdapter}, used for the load snapshot and for {@code merge}), which is why the fix is
 * here rather than in an {@code @Mutability} annotation that a {@code @Type} attribute ignores.
 */
public class TypedJsonBinaryType extends JsonBinaryType {

    @Override
    public Object deepCopy(Object value) {
        if (value == null) {
            return null;
        }
        JsonJavaTypeDescriptor json = getJavaTypeDescriptor();
        return json.fromString(json.toString(value));
    }
}
