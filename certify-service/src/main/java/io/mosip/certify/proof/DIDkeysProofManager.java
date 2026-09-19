/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.proof;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import io.ipfs.multibase.Multibase;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.io.IOException;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Holder keys named by a {@code did:key} (W3C did:key method): the multibase part is a multicodec-prefixed public key
 * for Ed25519 ({@code 0xed01}), secp256k1 ({@code 0xe701}), P-256 ({@code 0x1200}) or RSA ({@code 0x1205}).
 */
public class DIDkeysProofManager implements JwtProofKeyManager {
    public static final String DID_KEY_PREFIX = "did:key:";

    @Override
    public Optional<JWK> getKeyFromHeader(JWSHeader header) {
        if (Objects.nonNull(header.getJWK()))
            return Optional.ofNullable(header.getJWK());
        // the multibase part between "did:key:" and "#" (if present)
        String keyId = header.getKeyID();
        String multibase = keyId.substring(keyId.indexOf(DID_KEY_PREFIX) + DID_KEY_PREFIX.length());
        int hashIdx = multibase.indexOf('#');
        if (hashIdx != -1) {
            multibase = multibase.substring(0, hashIdx);
        }
        // the JWS key selector matches the header kid against the key's kid
        return fromMultibase(multibase).map(key -> withKid(key, keyId));
    }

    /**
     * The public key a multicodec-prefixed multibase string carries (did:key, {@code publicKeyMultibase}), without a kid.
     * Full prefix table: https://github.com/multiformats/multicodec/blob/master/table.csv;
     * https://w3c-ccg.github.io/did-key-spec/#signature-method-creation-algorithm
     */
    static Optional<JWK> fromMultibase(String multibase) {
        byte[] b = Multibase.decode(multibase);
        if ((b[0] == (byte) 0xed && b[1] == (byte) 0x01) && b.length == 34) {
            try {
                return Optional.of(JWK.parse(Map.of("kty", "OKP", "crv", "Ed25519",
                        "x", Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(b, 2, 34)))));
            } catch (ParseException e) {
                return Optional.empty();
            }
        } else if (b[0] == (byte) 0xe7 && b[1] == (byte) 0x01 && b.length == 35) {
            return Optional.of(ecKey("secp256k1", Curve.SECP256K1, b));
        } else if (b[0] == (byte) 0x80 && b[1] == (byte) 0x24 && b.length == 35) {
            // 0x1200 as an unsigned varint
            return Optional.of(ecKey("secp256r1", Curve.P_256, b));
        } else if (b[0] == (byte) 0x85 && b[1] == (byte) 0x24) {
            // 0x1205 as an unsigned varint: RSA, a PKCS#1 RSAPublicKey sequence
            try (ASN1InputStream asn1 = new ASN1InputStream(Arrays.copyOfRange(b, 2, b.length))) {
                ASN1Sequence seq = (ASN1Sequence) asn1.readObject();
                if (seq.size() != 2) {
                    return Optional.empty(); // missing modulus or exponent
                }
                BigInteger modulus = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
                BigInteger exponent = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
                return Optional.of(new RSAKey.Builder(Base64URL.encode(modulus), Base64URL.encode(exponent)).build());
            } catch (IOException e) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    private static JWK ecKey(String curveName, Curve curve, byte[] b) {
        ECCurve ecCurve = ECNamedCurveTable.getParameterSpec(curveName).getCurve();
        ECPoint point = ecCurve.decodePoint(Arrays.copyOfRange(b, 2, b.length));
        byte[] x = BigIntegers.asUnsignedByteArray(point.getAffineXCoord().toBigInteger());
        byte[] y = BigIntegers.asUnsignedByteArray(point.getAffineYCoord().toBigInteger());
        return new ECKey.Builder(curve, Base64URL.encode(x), Base64URL.encode(y)).build();
    }

    /** The same public key with {@code kid} set (Nimbus keys are immutable). */
    static JWK withKid(JWK key, String kid) {
        if (key instanceof ECKey ec) {
            return new ECKey.Builder(ec).keyID(kid).build();
        }
        if (key instanceof RSAKey rsa) {
            return new RSAKey.Builder(rsa).keyID(kid).build();
        }
        if (key instanceof OctetKeyPair okp) {
            return new OctetKeyPair.Builder(okp).keyID(kid).build();
        }
        return key;
    }

    @Override
    public Optional<String> getDID(JWSHeader header) {
        if (header.getKeyID().startsWith(DID_KEY_PREFIX)) {
            return Optional.of(header.getKeyID());
        }
        return Optional.empty();
    }
}
