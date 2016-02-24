/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Sequence;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.springframework.security.jwt.codec.Codecs.b64Decode;
import static org.springframework.security.jwt.codec.Codecs.utf8Encode;
import static org.springframework.util.StringUtils.isEmpty;

/**
 * A class that knows how to provide the signing and verification keys
 *
 *
 */
public class SignerProvider {

    private final Log logger = LogFactory.getLog(getClass());
    private String verifierKey = new RandomValueStringGenerator().generate();
    private String signingKey = verifierKey;
    private Signer signer = new MacSigner(verifierKey);
    private SignatureVerifier verifier = new MacSigner(signingKey);
    private String type = "MAC";
    private final Base64.Encoder base64encoder = Base64.getMimeEncoder(64, "\n".getBytes());

    public SignerProvider() {
        this(new RandomValueStringGenerator().generate());
    }

    public SignerProvider(String signingKey) {
        if (isEmpty(signingKey)) {
            throw new IllegalArgumentException("Signing key cannot be empty");
        }
        setSigningKey(signingKey);
    }

    public Signer getSigner() {
        return signer;
    }

    /**
     * @return the verifierKey
     */
    public String getVerifierKey() {
        return verifierKey;
    }

    public String getSigningKey() {
        return signingKey;
    }

    public String getType() {
        return type;
    }

    /**
     * @return true if the signer represents a public (asymmetric) key pair
     */
    public boolean isPublic() {
        return verifierKey.startsWith("-----BEGIN");
    }

    public SignatureVerifier getVerifier() {
        return verifier;
    }

    public String getRevocationHash(List<String> salts) {
        String result = "";
        for (String s : salts) {
            byte[] hashable = (result+ "###" + s).getBytes();
            result = Integer.toHexString(murmurhash3x8632(hashable, 0, hashable.length, 0xF0F0));
        }
        return result;
    }

    /**
     * Sets the JWT signing key and corresponding key for verifying siugnatures produced by this class.
     *
     * The signing key can be either a simple MAC key or an RSA
     * key. RSA keys should be in OpenSSH format,
     * as produced by <tt>ssh-keygen</tt>.
     *
     * @param signingKey the key to be used for signing JWTs.
     */
    public void setSigningKey(String signingKey) {
        Assert.hasText(signingKey);
        signingKey = signingKey.trim();

        this.signingKey = signingKey;


        if (isAssymetricKey(signingKey)) {
            KeyPair keyPair = parseKeyPair(signingKey);
            signer = new RsaSigner(signingKey);

            pemEncodePublicKey(keyPair);

            logger.debug("Configured with RSA signing key");
            try {
                verifier = new RsaVerifier(verifierKey);
            } catch (Exception e) {
                throw new RuntimeException("Unable to create an RSA verifier from verifierKey", e);
            }

            byte[] test = "test".getBytes();
            try {
                verifier.verify(test, signer.sign(test));
                logger.debug("Signing and verification RSA keys match");
            } catch (InvalidSignatureException e) {
                throw new RuntimeException("Signing and verification RSA keys do not match", e);
            }
            type = "RSA";
        }
        else {
            // Assume it's an HMAC key
            this.verifierKey = signingKey;
            MacSigner macSigner = new MacSigner(signingKey);
            signer = macSigner;
            verifier = macSigner;

            Assert.state(this.verifierKey == null || this.signingKey == this.verifierKey,
                    "For MAC signing you do not need to specify the verifier key separately, and if you do it must match the signing key");
            type = "MAC";
        }
    }

    protected void pemEncodePublicKey(KeyPair keyPair) {
        String begin = "-----BEGIN PUBLIC KEY-----\n";
        String end = "\n-----END PUBLIC KEY-----";
        byte[] data = keyPair.getPublic().getEncoded();
        String base64encoded = new String(base64encoder.encode(data));

        verifierKey = begin + base64encoded + end;
    }

    /**
     * @return true if the key has a public verifier
     */
    private boolean isAssymetricKey(String key) {
        return key.startsWith("-----BEGIN");
    }

    /**
     * This code is public domain.
     *
     *  The MurmurHash3 algorithm was created by Austin Appleby and put into the public domain.
     *  @see <a href="http://code.google.com/p/smhasher">http://code.google.com/p/smhasher</a>
     *  @see <a href="https://github.com/yonik/java_util/blob/master/src/util/hash/MurmurHash3.java">https://github.com/yonik/java_util/blob/master/src/util/hash/MurmurHash3.java</a>
     */
    public static int murmurhash3x8632(byte[] data, int offset, int len, int seed) {

        int c1 = 0xcc9e2d51;
        int c2 = 0x1b873593;

        int h1 = seed;
        int roundedEnd = offset + (len & 0xfffffffc);  // round down to 4 byte block

        for (int i = offset; i < roundedEnd; i += 4) {
            // little endian load order
            int k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24);
            k1 *= c1;
            k1 = (k1 << 15) | (k1 >>> 17);  // ROTL32(k1,15);
            k1 *= c2;

            h1 ^= k1;
            h1 = (h1 << 13) | (h1 >>> 19);  // ROTL32(h1,13);
            h1 = h1 * 5 + 0xe6546b64;
        }

        // tail
        int k1 = 0;

        switch(len & 0x03) {
            case 3:
                k1 = (data[roundedEnd + 2] & 0xff) << 16;
                // fallthrough
            case 2:
                k1 |= (data[roundedEnd + 1] & 0xff) << 8;
                // fallthrough
            case 1:
                k1 |= data[roundedEnd] & 0xff;
                k1 *= c1;
                k1 = (k1 << 15) | (k1 >>> 17);  // ROTL32(k1,15);
                k1 *= c2;
                h1 ^= k1;
            default:
        }

        // finalization
        h1 ^= len;

        // fmix(h1);
        h1 ^= h1 >>> 16;
        h1 *= 0x85ebca6b;
        h1 ^= h1 >>> 13;
        h1 *= 0xc2b2ae35;
        h1 ^= h1 >>> 16;

        return h1;
    }


    private static Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", Pattern.DOTALL);

    static KeyPair parseKeyPair(String pemData) {
        Matcher m = PEM_DATA.matcher(pemData.trim());

        if (!m.matches()) {
            throw new IllegalArgumentException("String is not PEM encoded data");
        }

        String type = m.group(1);
        final byte[] content = b64Decode(utf8Encode(m.group(2)));

        PublicKey publicKey;
        PrivateKey privateKey = null;

        try {
            KeyFactory fact = KeyFactory.getInstance("RSA");
            if (type.equals("RSA PRIVATE KEY")) {
                ASN1Sequence seq = ASN1Sequence.getInstance(content);
                if (seq.size() != 9) {
                    throw new IllegalArgumentException("Invalid RSA Private Key ASN1 sequence.");
                }
                org.bouncycastle.asn1.pkcs.RSAPrivateKey key = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(seq);
                RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
                RSAPrivateCrtKeySpec privSpec = new RSAPrivateCrtKeySpec(key.getModulus(), key.getPublicExponent(),
                        key.getPrivateExponent(), key.getPrime1(), key.getPrime2(), key.getExponent1(), key.getExponent2(),
                        key.getCoefficient());
                publicKey = fact.generatePublic(pubSpec);
                privateKey = fact.generatePrivate(privSpec);
            } else if (type.equals("PUBLIC KEY")) {
                KeySpec keySpec = new X509EncodedKeySpec(content);
                publicKey = fact.generatePublic(keySpec);
            } else if (type.equals("RSA PUBLIC KEY")) {
                ASN1Sequence seq = ASN1Sequence.getInstance(content);
                org.bouncycastle.asn1.pkcs.RSAPublicKey key = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(seq);
                RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
                publicKey = fact.generatePublic(pubSpec);
            } else {
                throw new IllegalArgumentException(type + " is not a supported format");
            }

            return new KeyPair(publicKey, privateKey);
        }
        catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
