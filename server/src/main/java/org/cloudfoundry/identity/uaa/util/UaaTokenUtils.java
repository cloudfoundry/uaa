/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.util;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.provider.ClientDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;

public final class UaaTokenUtils {

    public static final Pattern jwtPattern = Pattern.compile("[a-zA-Z0-9_\\-\\\\=]*\\.[a-zA-Z0-9_\\-\\\\=]*\\.[a-zA-Z0-9_\\-\\\\=]*");

    private UaaTokenUtils() { }

    public static String getRevocationHash(List<String> salts) {
        String result = "";
        for (String s : salts) {
            byte[] hashable = (result+ "###" + s).getBytes();
            result = Integer.toHexString(murmurhash3x8632(hashable, 0, hashable.length, 0xF0F0));
        }
        return result;
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

    public static Set<String> retainAutoApprovedScopes(Collection<String> requestedScopes, Set<String> autoApprovedScopes) {
        HashSet<String> result = new HashSet<>();
        if(autoApprovedScopes == null){
            return result;
        }
        if (autoApprovedScopes.contains("true")) {
            result.addAll(requestedScopes);
            return result;
        }
        Set<Pattern> autoApprovedScopePatterns = UaaStringUtils.constructWildcards(autoApprovedScopes);
        // Don't want to approve more than what's requested
        for (String scope : requestedScopes) {
            if (UaaStringUtils.matches(autoApprovedScopePatterns, scope)) {
                result.add(scope);
            }
        }
        return result;
    }

    public static boolean isUserToken(Map<String, Object> claims) {
        return !"client_credentials".equals(claims.get(GRANT_TYPE)) || (claims.get(SUB)!=null && claims.get(SUB) == claims.get(CID));
    }

    public static String getRevocableTokenSignature(ClientDetails client, UaaUser user) {
        String[] salts = new String[] {
            client.getClientId(),
            client.getClientSecret(),
            (String)client.getAdditionalInformation().get(ClientConstants.TOKEN_SALT),
            user == null ? null : user.getId(),
            user == null ? null : user.getPassword(),
            user == null ? null : user.getSalt(),
            user == null ? null : user.getEmail(),
            user == null ? null : user.getUsername(),
        };
        List<String> saltlist = new LinkedList<>();
        for (String s : salts) {
            if (s!=null) {
                saltlist.add(s);
            }
        }
        return getRevocationHash(saltlist);
    }

    public static String constructToken(Map<String, Object> header, Map<String, Object> claims, Signer signer) {
        byte[] headerJson = header == null ? new byte[0] : JsonUtils.writeValueAsBytes(header);
        byte[] claimsJson = claims == null ? new byte[0] : JsonUtils.writeValueAsBytes(claims);

        String headerBase64 = Base64.encodeBase64URLSafeString(headerJson);
        String claimsBase64 = Base64.encodeBase64URLSafeString(claimsJson);
        String headerAndClaims = headerBase64 + "." + claimsBase64;
        byte[] signature = signer.sign(headerAndClaims.getBytes());

        String signatureBase64 = Base64.encodeBase64URLSafeString(signature);

        return headerAndClaims + "." + signatureBase64;
    }

    public static boolean isJwtToken(String token) {
        return jwtPattern.matcher(token).matches();
    }
}
