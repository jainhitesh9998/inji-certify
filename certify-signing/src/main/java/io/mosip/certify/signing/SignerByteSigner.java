package io.mosip.certify.signing;

import com.danubetech.keyformats.crypto.ByteSigner;

/** Lets danubetech's Data Integrity {@code LdSigner}s sign through any {@link Signer} (keymanager, jca, x509 ...). */
public class SignerByteSigner extends ByteSigner {

    private final Signer signer;
    private final SigningKey key;
    private final SignatureAlgorithm algorithm;

    public SignerByteSigner(Signer signer, SigningKey key, SignatureAlgorithm algorithm) {
        super(algorithm.joseName());
        this.signer = signer;
        this.key = key;
        this.algorithm = algorithm;
    }

    @Override
    public byte[] sign(byte[] content) {
        return signer.signRaw(content, key, algorithm);
    }
}
