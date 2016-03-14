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

import org.bouncycastle.asn1.ASN1Sequence;
import org.cloudfoundry.identity.uaa.impl.config.LegacyTokenKey;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.springframework.security.jwt.codec.Codecs.b64Decode;
import static org.springframework.security.jwt.codec.Codecs.utf8Encode;

/**
 * A class that knows how to provide the signing and verification keys
 *
 *
 */
public final class SignerProvider {
    private SignerProvider() {}

    public static String getRevocationHash(List<String> salts) {
        String result = "";
        for (String s : salts) {
            byte[] hashable = (result+ "###" + s).getBytes();
            result = Integer.toHexString(murmurhash3x8632(hashable, 0, hashable.length, 0xF0F0));
        }
        return result;
    }

    public static KeyInfo getKey(String keyId) {
        return getKeys().get(keyId);
    }

    public static KeyInfo getActiveKey() {
        return getKeys().get(getActiveKeyId());
    }

    private static String getActiveKeyId() {
        IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
        if(config == null) return IdentityZoneHolder.getUaaZone().getConfig().getTokenPolicy().getActiveKeyId();
        String primaryKeyId = config.getTokenPolicy().getActiveKeyId();
        if(!StringUtils.hasText(primaryKeyId) && LegacyTokenKey.getLegacyTokenKeyInfo() != null) {
            primaryKeyId = LegacyTokenKey.LEGACY_TOKEN_KEY_ID;
        }
        if(!StringUtils.hasText(primaryKeyId)) {
            primaryKeyId = IdentityZoneHolder.getUaaZone().getConfig().getTokenPolicy().getActiveKeyId();
        }
        return primaryKeyId;
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
        KeyInfo legacyKey = LegacyTokenKey.getLegacyTokenKeyInfo();
        if(legacyKey != null) {
            keys.put(LegacyTokenKey.LEGACY_TOKEN_KEY_ID, legacyKey);
        }
        return keys;
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
