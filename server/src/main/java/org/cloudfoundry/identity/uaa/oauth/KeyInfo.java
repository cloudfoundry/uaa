/*
 * ****************************************************************************
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
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.oauth;

import org.bouncycastle.asn1.ASN1Sequence;
import org.cloudfoundry.identity.uaa.impl.config.LegacyTokenKey;
import org.cloudfoundry.identity.uaa.oauth.jwt.CommonSignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.CommonSigner;
import org.cloudfoundry.identity.uaa.oauth.jwt.Signer;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.springframework.security.jwt.codec.Codecs.b64Decode;
import static org.springframework.security.jwt.codec.Codecs.utf8Encode;

public class KeyInfo {
    private static Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", Pattern.DOTALL);
    private static final Base64.Encoder base64encoder = Base64.getMimeEncoder(64, "\n".getBytes());
    private String keyId;
    private String verifierKey = new RandomValueStringGenerator().generate();
    private String signingKey = verifierKey;
    private Signer signer = new CommonSigner(null, verifierKey);
    private SignatureVerifier verifier = new MacSigner(signingKey);
    private String type = "MAC";
    private RSAPublicKey rsaPublicKey;

    public static KeyInfo getKey(String keyId) {
        return getKeys().get(keyId);
    }

    public static Map<String, KeyInfo> getKeys() {
        IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
        if (config == null || config.getTokenPolicy().getKeys() == null || config.getTokenPolicy().getKeys().isEmpty()) {
            config = IdentityZoneHolder.getUaaZone().getConfig();
        }

        Map<String, KeyInfo> keys = new HashMap<>();
        for (Map.Entry<String, String> entry : config.getTokenPolicy().getKeys().entrySet()) {
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.setKeyId(entry.getKey());
            keyInfo.setSigningKey(entry.getValue());
            keys.put(entry.getKey(), keyInfo);
        }

        if(keys.isEmpty()) {
            keys.put(LegacyTokenKey.LEGACY_TOKEN_KEY_ID, LegacyTokenKey.getLegacyTokenKeyInfo());
        }

        return keys;
    }

    public static KeyInfo getActiveKey() {
        return getKeys().get(getActiveKeyId());
    }

    private static String getActiveKeyId() {
        IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
        if(config == null) return IdentityZoneHolder.getUaaZone().getConfig().getTokenPolicy().getActiveKeyId();
        String activeKeyId = config.getTokenPolicy().getActiveKeyId();

        Map<String, KeyInfo> keys;
        if(!StringUtils.hasText(activeKeyId) && (keys = getKeys()).size() == 1) {
            activeKeyId = keys.keySet().stream().findAny().get();
        }

        if(!StringUtils.hasText(activeKeyId)) {
            activeKeyId = IdentityZoneHolder.getUaaZone().getConfig().getTokenPolicy().getActiveKeyId();
        }

        if(!StringUtils.hasText(activeKeyId)) {
            activeKeyId = LegacyTokenKey.LEGACY_TOKEN_KEY_ID;
        }

        return activeKeyId;
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

    public RSAPublicKey getRsaPublicKey() {
        return rsaPublicKey;
    }

    /**
     * @return true if the KeyInfo represents an asymmetric (RSA) key pair
     */
    public boolean isAssymetricKey() {
        return isAssymetricKey(verifierKey);
    }

    public SignatureVerifier getVerifier() {
        return verifier;
    }

    /**
     * @return true if the string represents an asymmetric (RSA) key
     */
    public static boolean isAssymetricKey(String key) {
        return key.startsWith("-----BEGIN");
    }

    /**
     * Sets the JWT signing key and corresponding key for verifying siugnatures produced by this class.
     * <p>
     * The signing key can be either a simple MAC key or an RSA
     * key. RSA keys should be in OpenSSH format,
     * as produced by <tt>ssh-keygen</tt>.
     *
     * @param signingKey the key to be used for signing JWTs.
     */
    public void setSigningKey(String signingKey) {
        if (StringUtils.isEmpty(signingKey)) {
            throw new IllegalArgumentException("Signing key cannot be empty");
        }

        Assert.hasText(signingKey);
        signingKey = signingKey.trim();

        this.signingKey = signingKey;
        this.signer = new CommonSigner(keyId, signingKey);

        if (isAssymetricKey(signingKey)) {
            KeyPair keyPair = KeyInfo.parseKeyPair(signingKey);
            rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            verifierKey = pemEncodePublicKey(rsaPublicKey);
            type = "RSA";
        } else {
            // Assume it's an HMAC key
            this.verifierKey = signingKey;
            type = "MAC";
        }

        verifier = new CommonSignatureVerifier(verifierKey);
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        if(!StringUtils.hasText(keyId)){
            throw new IllegalArgumentException("KeyId should not be null or empty");
        }
        this.keyId = keyId;
        this.signer = new CommonSigner(keyId, signingKey);
    }

    public static KeyPair parseKeyPair(String pemData) {
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
                RSAPrivateCrtKeySpec privSpec = new RSAPrivateCrtKeySpec(
                    key.getModulus(),
                    key.getPublicExponent(),
                    key.getPrivateExponent(),
                    key.getPrime1(),
                    key.getPrime2(),
                    key.getExponent1(),
                    key.getExponent2(),
                    key.getCoefficient()
                );
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

    public static String pemEncodePublicKey(PublicKey publicKey) {
        String begin = "-----BEGIN PUBLIC KEY-----\n";
        String end = "\n-----END PUBLIC KEY-----";
        byte[] data = publicKey.getEncoded();
        String base64encoded = new String(base64encoder.encode(data));

        return begin + base64encoded + end;
    }
}
