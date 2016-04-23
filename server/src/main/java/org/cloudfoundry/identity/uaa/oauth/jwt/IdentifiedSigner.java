package org.cloudfoundry.identity.uaa.oauth.jwt;

public class IdentifiedSigner implements Signer {
    private final String id;
    private final org.springframework.security.jwt.crypto.sign.Signer signer;

    public IdentifiedSigner(String id, org.springframework.security.jwt.crypto.sign.Signer signer) {
        this.id = id;
        this.signer = signer;
    }

    @Override
    public String keyId() {
        return id;
    }

    @Override
    public byte[] sign(byte[] bytes) {
        return signer.sign(bytes);
    }

    @Override
    public String algorithm() {
        return signer.algorithm();
    }
}
