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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSetTransformer;
import com.nimbusds.jwt.SignedJWT;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.ParseException;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.util.ObjectUtils.isNotEmpty;
import static org.springframework.util.StringUtils.hasText;

public final class UaaTokenUtils {

    public static final Pattern jwtPattern = Pattern.compile("[a-zA-Z0-9_\\-\\\\=]*\\.[a-zA-Z0-9_\\-\\\\=]*\\.[a-zA-Z0-9_\\-\\\\=]*");

    private UaaTokenUtils() {
    }

    public static String getRevocationHash(List<String> salts) {
        String result = "";
        for (String s : salts) {
            byte[] hashable = (result + "###" + s).getBytes();
            result = Integer.toHexString(murmurhash3x8632(hashable, 0, hashable.length, 0xF0F0));
        }
        return result;
    }

    /**
     * This code is public domain.
     * <p>
     * The MurmurHash3 algorithm was created by Austin Appleby and put into the public domain.
     *
     * @see <a href="http://code.google.com/p/smhasher">http://code.google.com/p/smhasher</a>
     * @see <a href="https://github.com/yonik/java_util/blob/master/src/util/hash/MurmurHash3.java">https://github.com/yonik/java_util/blob/master/src/util/hash/MurmurHash3.java</a>
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

        switch (len & 0x03) {
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
                break;
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
        if (autoApprovedScopes == null) {
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
        if (claims.get(GRANT_TYPE) != null) {
            return !GRANT_TYPE_CLIENT_CREDENTIALS.equals(claims.get(GRANT_TYPE));
        }
        if (claims.get(SUB) != null) {
            if (claims.get(SUB).equals(claims.get(USER_ID))) {
                return true;
            } else if (claims.get(SUB).equals(claims.get(CID))) {
                return false;
            }
        }
        //err on the side of caution
        return true;
    }

    public static String getRevocableTokenSignature(ClientDetails client, String clientSecret, UaaUser user) {
        String tokenSalt = (String) client.getAdditionalInformation().get(ClientConstants.TOKEN_SALT);
        String clientId = client.getClientId();

        return getRevocableTokenSignature(user, tokenSalt, clientId, clientSecret);
    }

    public static String getRevocableTokenSignature(UaaUser user, String tokenSalt, String clientId, String clientSecret) {
        String[] salts = new String[]{
                clientId,
                clientSecret,
                tokenSalt,
                user == null ? null : user.getId(),
                user == null ? null : user.getPassword(),
                user == null ? null : user.getSalt(),
                user == null ? null : user.getEmail(),
                user == null ? null : user.getUsername(),
        };
        List<String> saltlist = new LinkedList<>();
        for (String s : salts) {
            if (s != null) {
                saltlist.add(s);
            }
        }
        return getRevocationHash(saltlist);
    }

    public static String constructToken(Map<String, Object> header, Map<String, Object> claims, JWSSigner signer) {
        try {
            JWSHeader joseHeader = JWSHeader.parse(header);
            JWTClaimsSet claimsSet = JWTClaimsSet.parse(claims);
            SignedJWT signedJWT = new SignedJWT(joseHeader, claimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (ParseException | JOSEException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static boolean isJwtToken(String token) {
        return jwtPattern.matcher(token).matches();
    }

    public static String constructTokenEndpointUrl(String issuer, IdentityZone identityZone) throws URISyntaxException {
        URI uri;
        if (!identityZone.isUaa()) {
            String zoneIssuer = identityZone.getConfig() != null ? identityZone.getConfig().getIssuer() : null;
            if (zoneIssuer != null) {
                uri = validateIssuer(zoneIssuer);
                return UriComponentsBuilder.fromUri(uri).pathSegment("oauth/token").build().toUriString();
            }
        }
        uri = validateIssuer(issuer);
        String hostToUse = uri.getHost();
        if (hasText(identityZone.getSubdomain())) {
            hostToUse = identityZone.getSubdomain() + "." + hostToUse;
        }
        return UriComponentsBuilder.fromUri(uri).host(hostToUse).pathSegment("oauth/token").build().toUriString();
    }

    private static URI validateIssuer(String issuer) throws URISyntaxException {
        try {
            new URL(issuer);
        } catch (MalformedURLException x) {
            throw new URISyntaxException(issuer, x.getMessage());
        }
        return new URI(issuer);
    }

    public static boolean hasRequiredUserAuthorities(Collection<String> requiredGroups, Collection<? extends GrantedAuthority> userGroups) {
        return hasRequiredUserGroups(requiredGroups,
                ofNullable(userGroups).orElse(emptySet())
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()
        );
    }

    public static boolean hasRequiredUserGroups(Collection<String> requiredGroups, Collection<String> userGroups) {
        return ofNullable(userGroups).orElse(emptySet())
                .containsAll(ofNullable(requiredGroups).orElse(emptySet()));
    }

    public static <T> T getClaims(String jwtToken, Class<T> toClazz) {
        Object claims;
        try {
            claims = JwtHelper.decode(jwtToken).getClaimSet().toType(getClaimsSetTransformer(toClazz));
        } catch (Exception ex) {
            throw new InvalidTokenException("Invalid token (could not decode): " + jwtToken, ex);
        }
        return claims != null ? (T) claims : (T) new Object();
    }

    public static Claims getClaimsFromTokenString(String jwtToken) {
        return getClaims(jwtToken, Claims.class);
    }

    public static <T> JWTClaimsSetTransformer<T> getClaimsSetTransformer(Class<T> toClazz) {
        return claimsSet -> {
            Map<String, Object> claimMap = claimsSet.toJSONObject();
            Object audObject = claimsSet.getAudience();
            if (isNotEmpty(audObject)) {
                claimMap.put(ClaimConstants.AUD, claimsSet.getAudience());
            }
            return JsonUtils.convertValue(claimMap, toClazz);
        };
    }
}
