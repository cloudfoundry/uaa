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

package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.BigIntegerUtils;
import org.apache.commons.collections.map.HashedMap;
import org.bouncycastle.asn1.ASN1Sequence;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeyResponse;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

import java.math.BigInteger;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.RSA;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyUse.sig;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.springframework.security.jwt.codec.Codecs.b64Decode;
import static org.springframework.security.jwt.codec.Codecs.utf8Encode;

public class RsaJsonWebKeyTests {
    private static final String ISSUER = "http://localhost:8080/issuer";

    @Test
    public void create_key_from_pem_string() {
        KeyInfo keyInfo = KeyInfoBuilder.build("id", sampleRsaPrivateKey, ISSUER);
        assertEquals("RSA", keyInfo.type());
        assertNotNull(keyInfo.getVerifier());

        JsonWebKey key = new JsonWebKey(KeyInfoBuilder.build("id", sampleRsaPrivateKey, ISSUER).getJwkMap()).setKid("id");

        assertEquals(RSA, key.getKty());
        assertEquals("RSA", key.getKeyProperties().get("kty"));
        assertEquals("id", key.getKid());
        assertEquals(sig, key.getUse());
        assertEquals("sig", key.getKeyProperties().get("use"));
        assertNotNull(key.getValue());

        PublicKey pk = parseKeyPair(keyInfo.verifierKey()).getPublic();

        BigInteger exponent = ((RSAPublicKey) pk).getPublicExponent();
        BigInteger modulus = ((RSAPublicKey) pk).getModulus();
        java.util.Base64.Encoder encoder = java.util.Base64.getUrlEncoder().withoutPadding();
        assertEquals(encoder.encodeToString(exponent.toByteArray()), key.getKeyProperties().get("e"));
        assertEquals(encoder.encodeToString(BigIntegerUtils.toBytesUnsigned(modulus)), key.getKeyProperties().get("n"));
    }

    @Test
    public void create_key_from_public_pem_string() {
        KeyInfo keyInfo = KeyInfoBuilder.build("id", sampleRsaPrivateKey, ISSUER);
        assertEquals("RSA", keyInfo.type());
        assertNotNull(keyInfo.getVerifier());

        Map<String, Object> jwkMap = keyInfo.getJwkMap();
        JsonWebKey jsonWebKey = new JsonWebKey(jwkMap);
        JsonWebKey key = jsonWebKey.setKid("id");
        assertEquals(RSA, key.getKty());
        assertEquals("RSA", key.getKeyProperties().get("kty"));
        assertEquals("id", key.getKid());
        assertEquals(sig, key.getUse());
        assertEquals("sig", key.getKeyProperties().get("use"));
        assertNotNull(key.getValue());

        PublicKey pk = parseKeyPair(keyInfo.verifierKey()).getPublic();
        BigInteger exponent = ((RSAPublicKey) pk).getPublicExponent();
        BigInteger modulus = ((RSAPublicKey) pk).getModulus();

        java.util.Base64.Encoder encoder = java.util.Base64.getUrlEncoder().withoutPadding();
        assertEquals(encoder.encodeToString(exponent.toByteArray()), key.getKeyProperties().get("e"));
        assertEquals(encoder.encodeToString(BigIntegerUtils.toBytesUnsigned(modulus)), key.getKeyProperties().get("n"));
    }

    @Test
    public void deserialize_azure_keys() {
        deserialize_azure_keys(sampleRsaKeys);
    }

    @Test
    public void ensure_that_duplicates_are_removed() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(sampleRsaKeys, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        List<JsonWebKey> list = new ArrayList<>(keys.getKeys());
        list.addAll(keys.getKeys());
        assertEquals(6, list.size());
        keys = new JsonWebKeySet<>(list);
        deserialize_azure_keys(JsonUtils.writeValueAsString(keys));
    }

    @Test
    public void ensure_that_duplicates_get_the_last_object() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(sampleRsaKeys, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        List<JsonWebKey> list = new ArrayList<>(keys.getKeys());
        list.addAll(keys.getKeys());
        assertEquals(6, list.size());

        Map<String, Object> p = new HashedMap(list.get(5).getKeyProperties());
        p.put("issuer", ISSUER);
        list.add(new VerificationKeyResponse(p));
        assertEquals(7, list.size());

        keys = new JsonWebKeySet<>(list);
        keys = deserialize_azure_keys(JsonUtils.writeValueAsString(keys));

        assertEquals(ISSUER, keys.getKeys().get(2).getKeyProperties().get("issuer"));
    }

    @Test
    public void test_required_properties() {
        Map<String, Object> map = new HashMap();
        test_create_with_error(map);
        map.put("kty", "RSA");
        new VerificationKeyResponse(map);
    }

    @Test
    public void test_equals() {
        Map<String, Object> p1 = new HashMap<>();
        p1.put("kty", "RSA");
        Map<String, Object> p2 = new HashMap<>(p1);
        assertEquals(new VerificationKeyResponse(p1), new VerificationKeyResponse(p2));
        p1.put("kid", "id");
        assertNotEquals(new VerificationKeyResponse(p1), new VerificationKeyResponse(p2));
        p2.put("kid", "id");
        assertEquals(new VerificationKeyResponse(p1), new VerificationKeyResponse(p2));
        p1.put("issuer", "issuer1");
        p2.put("issuer", "issuer2");
        assertEquals(new VerificationKeyResponse(p1), new VerificationKeyResponse(p2));
        p1.remove("kid");
        p2.remove("kid");
        assertNotEquals(new VerificationKeyResponse(p1), new VerificationKeyResponse(p2));
        p2.put("issuer", "issuer1");
        assertEquals(new VerificationKeyResponse(p1), new VerificationKeyResponse(p2));
    }

    private void test_create_with_error(Map p) {
        try {
            new VerificationKeyResponse(p);
            fail("Creation of key with properties:" + p + " should fail.");
        } catch (IllegalArgumentException ignored) {
        }
    }


    private JsonWebKeySet<JsonWebKey> deserialize_azure_keys(String json) {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(json, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        assertNotNull(keys);
        assertNotNull(keys.getKeys());
        assertEquals(3, keys.getKeys().size());
        for (JsonWebKey key : keys.getKeys()) {
            assertNotNull(key);
            assertNotNull(JsonWebKey.getRsaPublicKey(key));

        }
        return keys;
    }

    private static final String sampleRsaPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
      "MIICXgIBAAKBgQDfTLadf6QgJeS2XXImEHMsa+1O7MmIt44xaL77N2K+J/JGpfV3\n" +
      "AnkyB06wFZ02sBLB7hko42LIsVEOyTuUBird/3vlyHFKytG7UEt60Fl88SbAEfsU\n" +
      "JN1i1aSUlunPS/NCz+BKwwKFP9Ss3rNImE9Uc2LMvGy153LHFVW2zrjhTwIDAQAB\n" +
      "AoGBAJDh21LRcJITRBQ3CUs9PR1DYZPl+tUkE7RnPBMPWpf6ny3LnDp9dllJeHqz\n" +
      "a3ACSgleDSEEeCGzOt6XHnrqjYCKa42Z+Opnjx/OOpjyX1NAaswRtnb039jwv4gb\n" +
      "RlwT49Y17UAQpISOo7JFadCBoMG0ix8xr4ScY+zCSoG5v0BhAkEA8llNsiWBJF5r\n" +
      "LWQ6uimfdU2y1IPlkcGAvjekYDkdkHiRie725Dn4qRiXyABeaqNm2bpnD620Okwr\n" +
      "sf7LY+BMdwJBAOvgt/ZGwJrMOe/cHhbujtjBK/1CumJ4n2r5V1zPBFfLNXiKnpJ6\n" +
      "J/sRwmjgg4u3Anu1ENF3YsxYabflBnvOP+kCQCQ8VBCp6OhOMcpErT8+j/gTGQUL\n" +
      "f5zOiPhoC2zTvWbnkCNGlqXDQTnPUop1+6gILI2rgFNozoTU9MeVaEXTuLsCQQDC\n" +
      "AGuNpReYucwVGYet+LuITyjs/krp3qfPhhByhtndk4cBA5H0i4ACodKyC6Zl7Tmf\n" +
      "oYaZoYWi6DzbQQUaIsKxAkEA2rXQjQFsfnSm+w/9067ChWg46p4lq5Na2NpcpFgH\n" +
      "waZKhM1W0oB8MX78M+0fG3xGUtywTx0D4N7pr1Tk2GTgNw==\n" +
      "-----END RSA PRIVATE KEY-----";

    private static final String sampleRsaKeys = "{\n" +
      "    \"keys\": [\n" +
      "        {\n" +
      "            \"e\": \"AQAB\",\n" +
      "            \"issuer\": \"https://login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/v2.0\",\n" +
      "            \"kid\": \"YbRAQRYcE_motWVJKHrwLBbd_9s\",\n" +
      "            \"kty\": \"RSA\",\n" +
      "            \"n\": \"vbcFrj193Gm6zeo5e2_y54Jx49sIgScv-2JO-n6NxNqQaKVnMkHcz-S1j2FfpFngotwGMzZIKVCY1SK8SKZMFfRTU3wvToZITwf3W1Qq6n-h-abqpyJTaqIcfhA0d6kEAM5NsQAKhfvw7fre1QicmU9LWVWUYAayLmiRX6o3tktJq6H58pUzTtx_D0Dprnx6z5sW-uiMipLXbrgYmOez7htokJVgDg8w-yDFCxZNo7KVueUkLkxhNjYGkGfnt18s7ZW036WoTmdaQmW4CChf_o4TLE5VyGpYWm7I_-nV95BBvwlzokVVKzveKf3l5UU3c6PkGy-BB3E_ChqFm6sPWw\",\n" +
      "            \"use\": \"sig\",\n" +
      "            \"x5c\": [\n" +
      "                \"MIIC4jCCAcqgAwIBAgIQfQ29fkGSsb1J8n2KueDFtDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE2MDQxNzAwMDAwMFoXDTE4MDQxNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL23Ba49fdxpus3qOXtv8ueCcePbCIEnL/tiTvp+jcTakGilZzJB3M/ktY9hX6RZ4KLcBjM2SClQmNUivEimTBX0U1N8L06GSE8H91tUKup/ofmm6qciU2qiHH4QNHepBADOTbEACoX78O363tUInJlPS1lVlGAGsi5okV+qN7ZLSauh+fKVM07cfw9A6a58es+bFvrojIqS1264GJjns+4baJCVYA4PMPsgxQsWTaOylbnlJC5MYTY2BpBn57dfLO2VtN+lqE5nWkJluAgoX/6OEyxOVchqWFpuyP/p1feQQb8Jc6JFVSs73in95eVFN3Oj5BsvgQdxPwoahZurD1sCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAe5RxtMLU2i4/vN1YacncR3GkOlbRv82rll9cd5mtVmokAw7kwbFBFNo2vIVkun+n+VdJf+QRzmHGm3ABtKwz3DPr78y0qdVFA3h9P60hd3wqu2k5/Q8s9j1Kq3u9TIEoHlGJqNzjqO7khX6VcJ6BRLzoefBYavqoDSgJ3mkkYCNqTV2ZxDNks3obPg4yUkh5flULH14TqlFIOhXbsd775aPuMT+/tyqcc6xohU5NyYA63KtWG1BLDuF4LEF84oNPcY9i0n6IphEGgz20H7YcLRNjU55pDbWGdjE4X8ANb23kAc75RZn9EY4qYCiqeIAg3qEVKLnLUx0fNKMHmuedjg==\"\n" +
      "            ],\n" +
      "            \"x5t\": \"YbRAQRYcE_motWVJKHrwLBbd_9s\"\n" +
      "        },\n" +
      "        {\n" +
      "            \"e\": \"AQAB\",\n" +
      "            \"issuer\": \"https://login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/v2.0\",\n" +
      "            \"kid\": \"I6oBw4VzBHOqleGrV2AJdA5EmXc\",\n" +
      "            \"kty\": \"RSA\",\n" +
      "            \"n\": \"oRcN8f34zyc04f1l-G4iff5SuR1QE245pzd8eEpWJOm5-qAGXgQbxpw7eIElYweG5f09L_gCCKTbR80b_sGcB2vv_RvRd246HObCtUjB4tDkmS6J-ut1LRwXdaInoT31WybV5hhpNwfjGTkY2Db-wOHNPTfHNeI-FrvgxwtLnRWBuqgEiHawpVwLsTn8YV7kdjAQ10L9R0j7z0fCZJp14U7lDGu5r5ViT1aG0xSQ4SOjyt0FkHTrM5inED9af1LHVFiM6sIEu-Wude-8m0CqWFoKpY5JdP79BZPkB61y8sFKLa3aRanKPz9BzW-ep7Pe99bqoDLNNoDpNtJv7yOXMw\",\n" +
      "            \"use\": \"sig\",\n" +
      "            \"x5c\": [\n" +
      "                \"MIIDBTCCAe2gAwIBAgIQPLxWKJ0EEqNLJ1eIGhsS/jANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE2MDkwNTAwMDAwMFoXDTE4MDkwNjAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKEXDfH9+M8nNOH9ZfhuIn3+UrkdUBNuOac3fHhKViTpufqgBl4EG8acO3iBJWMHhuX9PS/4Agik20fNG/7BnAdr7/0b0XduOhzmwrVIweLQ5JkuifrrdS0cF3WiJ6E99Vsm1eYYaTcH4xk5GNg2/sDhzT03xzXiPha74McLS50VgbqoBIh2sKVcC7E5/GFe5HYwENdC/UdI+89HwmSadeFO5Qxrua+VYk9WhtMUkOEjo8rdBZB06zOYpxA/Wn9Sx1RYjOrCBLvlrnXvvJtAqlhaCqWOSXT+/QWT5AetcvLBSi2t2kWpyj8/Qc1vnqez3vfW6qAyzTaA6TbSb+8jlzMCAwEAAaMhMB8wHQYDVR0OBBYEFJuS8ySZ1mYXPa4Sq1nSrl1G41rXMA0GCSqGSIb3DQEBCwUAA4IBAQBxf5BldsfSq05AAnco9NlToMPsXf46GbInCC/o2R+4WbwJ3uzZe+2/o86nI5gFcq/hGy/HXZXdsWj6py6fI0T5Av0GlhCxAuCmsMoyEMmoGdEnSL6cMfAA57lsAgDGVOB3OdzZoK3um1fpb0paXv1eColOIYsL9lY91Bk4P3E496IDAbkjCjiFzsiQerlmzXSHhvSjvas2g6VTQEwj8/9l4xZO1O3BhExdZHWAkUW1ZciTSB4Ite5bcAHWWBRqMUB7Da5Yj674SocHFhGM+9iM6xaJfMSYjlDFB2rNDSUv8ZLIyDpHB9Ry9N8p7znyixhpiWn0nPVqfX84LMckrgfs\"\n" +
      "            ],\n" +
      "            \"x5t\": \"I6oBw4VzBHOqleGrV2AJdA5EmXc\"\n" +
      "        },\n" +
      "        {\n" +
      "            \"e\": \"AQAB\",\n" +
      "            \"issuer\": \"https://login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/v2.0\",\n" +
      "            \"kid\": \"RrQqu9rydBVRWmcocuXUb20HGRM\",\n" +
      "            \"kty\": \"RSA\",\n" +
      "            \"n\": \"kqE2PL51yFq3gfJtTHzoUq9sNyIXXLoAu40qihZKzmDkcd0qFJkITQYooSTE6kFJWeE1cN0PAk4lYyZHgFqI03CbM-gXslotiF065TH_xGq-I0mvWRz32l15-DZugtji8T04uLo9jWJE7qem6eE6cSlmpw4gabnIW2Chvi2KWe3ChVhOpiCh2v1wt8TO_QqnVMe6BNo91N8z7RtDEs-XhAWKZ3-y3eK7kGjNz5SPLjQ8ZRsAdSGYQTu_o5ygtjUiy1xqIHJz1F4u8WueQt5n6_DKNVuZw6E-VBWQWiQPAhDom9SVy12Rafc38_Tt2MTTXR0Xn1em6Tn-IWsLNwZc4w\",\n" +
      "            \"use\": \"sig\",\n" +
      "            \"x5c\": [\n" +
      "                \"MIIDBTCCAe2gAwIBAgIQHukklH1Oi5lG9RSJH3l1tDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE2MTAxNjAwMDAwMFoXDTE4MTAxNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJKhNjy+dchat4HybUx86FKvbDciF1y6ALuNKooWSs5g5HHdKhSZCE0GKKEkxOpBSVnhNXDdDwJOJWMmR4BaiNNwmzPoF7JaLYhdOuUx/8RqviNJr1kc99pdefg2boLY4vE9OLi6PY1iRO6npunhOnEpZqcOIGm5yFtgob4tilntwoVYTqYgodr9cLfEzv0Kp1THugTaPdTfM+0bQxLPl4QFimd/st3iu5Bozc+Ujy40PGUbAHUhmEE7v6OcoLY1IstcaiByc9ReLvFrnkLeZ+vwyjVbmcOhPlQVkFokDwIQ6JvUlctdkWn3N/P07djE010dF59Xpuk5/iFrCzcGXOMCAwEAAaMhMB8wHQYDVR0OBBYEFIaXDebTVWUsKdVaPWYQgHO3IhFnMA0GCSqGSIb3DQEBCwUAA4IBAQByhTRtSxoWXZ6iSJgoTt/NdQIuHtgu2HWtd0teIJgBtPGUyLJ+pSXTRUr7hp41WpjcPz6rwq615Xm3pzoGbl+5SK3XlQR0o4/MMa79k+41igmkPhHUBVosaOH1QgpzZATFX12kJxaDOlCjuBLv9gE1y93FbnUkcKItFvbMOXwn38KbzsiYF6cOTtJ4lAfMFoHFkpHWkEkrhhOJMXFpDbMP5ELSOy8usdQJdHHxeHoM28zTaU/SkYZHjqMmrWl6J4fUV7R4aZy7zRZ/NvrPqvhZH2YXGdiEAOvH+VtGDCPOZLjKxJFAgjmpwv4KErKmxCxH8SHp+c0mg3l5QpO0C0v0\"\n" +
      "            ],\n" +
      "            \"x5t\": \"RrQqu9rydBVRWmcocuXUb20HGRM\"\n" +
      "        }\n" +
      "    ]\n" +
      "}";
    private static Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", Pattern.DOTALL);

    private KeyPair parseKeyPair(String pemData) {
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
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // see https://github.com/cloudfoundry/uaa/issues/1514
    private static final String issue1514Key = "-----BEGIN PUBLIC KEY-----\\n" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyH6kYCP29faDAUPKtei3\\n"
        + "V/Zh8eCHyHRDHrD0iosvgHuaakK1AFHjD19ojuPiTQm8r8nEeQtHb6mDi1LvZ03e\\n" + "EWxpvWwFfFVtCyBqWr5wn6IkY+ZFXfERLn2NCn6sMVxcFV12sUtuqD+jrW8MnTG7\\n"
        + "hofQqxmVVKKsZiXCvUSzfiKxDgoiRuD3MJSoZ0nQTHVmYxlFHuhTEETuTqSPmOXd\\n" + "/xJBVRi5WYCjt1aKRRZEz04zVEBVhVkr2H84qcVJHcfXFu4JM6dg0nmTjgd5cZUN\\n"
        + "cwA1KhK2/Qru9N0xlk9FGD2cvrVCCPWFPvZ1W7U7PBWOSBBH6GergA+dk2vQr7Ho\\n" + "lQIDAQAB\\n" + "-----END PUBLIC KEY-----";

    public static final String issue1514KeyJson = "{\n" +
        "    \"alg\": \"RS256\",\n" +
        "    \"e\": \"AQAB\",\n" +
        "    \"kid\": \"legacy\",\n" +
        "    \"kty\": \"RSA\",\n" +
        "    \"n\": \"yH6kYCP29faDAUPKtei3V_Zh8eCHyHRDHrD0iosvgHuaakK1AFHjD19ojuPiTQm8r8nEeQtHb6mDi1LvZ03eEWxpvWwFfFVtCyBqWr5wn6IkY-ZFXfERLn2NCn6sMVxcFV12sUtuqD-jrW8MnTG7hofQqxmVVKKsZiXCvUSzfiKxDgoiRuD3MJSoZ0nQTHVmYxlFHuhTEETuTqSPmOXd_xJBVRi5WYCjt1aKRRZEz04zVEBVhVkr2H84qcVJHcfXFu4JM6dg0nmTjgd5cZUNcwA1KhK2_Qru9N0xlk9FGD2cvrVCCPWFPvZ1W7U7PBWOSBBH6GergA-dk2vQr7HolQ\",\n" +
        "    \"use\": \"sig\",\n" +
        "    \"value\": \"" + issue1514Key +"\"\n" +
        "}";
    @Test
    public void test_jwtKeyEndoding() {
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.deserialize(issue1514KeyJson);
        PublicKey pk = parseKeyPair(issue1514Key.replace("\\n", "\n")).getPublic();
        assertNotNull(keys);
        assertNotNull(keys.getKeys());
        JsonWebKey key = keys.getKeys().get(0);
        BigInteger exponent = ((RSAPublicKey) pk).getPublicExponent();
        BigInteger modulus = ((RSAPublicKey) pk).getModulus();
        assertEquals(key.getKeyProperties().get("n"), Base64URL.encode(((RSAPublicKey) pk).getModulus()).toString());
    }
}
