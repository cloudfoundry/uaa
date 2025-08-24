/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.util;

import com.google.common.collect.Lists;
import com.nimbusds.jwt.JWTClaimsSet;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenRevokedException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnauthorizedClientException;
import org.cloudfoundry.identity.uaa.oauth.jwt.ChainedSignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.jwt.SignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.Verifier;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUD;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.REVOCATION_SIGNATURE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REFRESH_TOKEN_SUFFIX;
import static org.cloudfoundry.identity.uaa.util.UaaTokenUtils.isUserToken;

public abstract class JwtTokenSignedByThisUAA {
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenSignedByThisUAA.class);
    private final Map<String, Object> claims;
    private final Jwt tokenJwt;
    private final String token;

    private final KeyInfoService keyInfoService;

    public static JwtTokenSignedByThisUAA buildAccessTokenValidator(String tokenJwtValue, KeyInfoService keyInfoService) {
        AccessTokenValidation validator = new AccessTokenValidation(tokenJwtValue, keyInfoService);
        validator.checkSignature();
        return validator;
    }

    public static JwtTokenSignedByThisUAA buildRefreshTokenValidator(String tokenJwtValue, KeyInfoService keyInfoService) {
        RefreshTokenValidation refreshTokenValidation = new RefreshTokenValidation(tokenJwtValue, keyInfoService);
        refreshTokenValidation.checkSignature();
        return refreshTokenValidation;
    }

    public static JwtTokenSignedByThisUAA buildIdTokenValidator(String tokenJwtValue, ChainedSignatureVerifier verifier, KeyInfoService keyInfoService) {
        IdTokenValidation idTokenValidation = new IdTokenValidation(tokenJwtValue, keyInfoService);
        idTokenValidation.checkSignature(verifier);
        return idTokenValidation;
    }

    abstract ScopeClaimKey scopeClaimKey();

    @NotNull
    List<String> requestedScopes() {
        return readScopesFromClaim(scopeClaimKey());
    }

    private JwtTokenSignedByThisUAA(String token, KeyInfoService keyInfoService) {
        this.token = token;

        this.tokenJwt = JwtHelper.decode(token);
        this.keyInfoService = keyInfoService;
        this.claims = tokenJwt.getClaimSet().toType(UaaTokenUtils.getClaimsSetTransformer(Map.class));
    }

    private SignatureVerifier fetchSignatureVerifierFromToken(Jwt tokenJwt) {
        String kid = tokenJwt.getHeader().getKid();
        if (kid == null) {
            throw new InvalidTokenException("kid claim not found in JWT token header");
        }

        KeyInfo signingKey = keyInfoService.getKey(kid, tokenJwt.getHeader().getAlg());
        if (signingKey == null) {
            throw new InvalidTokenException("Token header claim [kid] references unknown signing key : [%s]".formatted(kid
            ));
        }

        return signingKey.getVerifier();
    }

    public JwtTokenSignedByThisUAA checkSignature() {
        return checkSignature(fetchSignatureVerifierFromToken(this.tokenJwt));
    }

    public JwtTokenSignedByThisUAA checkSignature(Verifier verifier) {
        try {
            this.tokenJwt.verifySignature(verifier);
        } catch (RuntimeException ex) {
            logger.debug("Invalid token (could not verify signature)", ex);
            throw new InvalidTokenException("Could not verify token signature.", new UnauthorizedClientException(token));
        }
        return this;
    }

    public JwtTokenSignedByThisUAA checkIssuer(String issuer) {
        if (issuer == null) {
            return this;
        }

        JWTClaimsSet jwtClaimsSet = getJwt().getClaimSet();
        if (jwtClaimsSet.getIssuer() == null) {
            throw new InvalidTokenException("Token does not bear an ISS claim.", null);
        }

        if (!equals(issuer, jwtClaimsSet.getIssuer())) {
            throw new InvalidTokenException("Invalid issuer (" + jwtClaimsSet.getIssuer() + ") for token did not match expected: " + issuer, null);
        }
        return this;
    }

    protected JwtTokenSignedByThisUAA checkExpiry(Instant asOf) {
        JWTClaimsSet jwtClaimsSet = getJwt().getClaimSet();
        Date expiry = jwtClaimsSet.getExpirationTime();
        if (expiry == null || asOf == null || asOf.isAfter(expiry.toInstant())) {
            throw new InvalidTokenException("Token does not bear a valid EXP claim.", null);
        }
        return this;
    }

    public JwtTokenSignedByThisUAA checkExpiry() {
        return checkExpiry(Instant.now());
    }

    protected JwtTokenSignedByThisUAA checkUser(Function<String, UaaUser> getUser) {
        if (!isUserToken(claims)) {
            throw new InvalidTokenException("Token is not a user token.", null);
        }

        if (!claims.containsKey(USER_ID)) {
            throw new InvalidTokenException("Token does not bear a USER_ID claim.", null);
        }

        String userId;
        Object userIdClaim = claims.get(USER_ID);
        try {
            userId = (String) userIdClaim;
        } catch (ClassCastException ex) {
            throw new InvalidTokenException("Token bears an invalid or unparseable USER_ID claim.", ex);
        }

        if (userId == null) {
            throw new InvalidTokenException("Token has a null USER_ID claim.", null);
        } else {
            checkScope(getUser, userId);
        }
        return this;
    }

    void checkScope(Function<String, UaaUser> getUser, String userId) {
        UaaUser user;
        try {
            user = getUser.apply(userId);
        } catch (UsernameNotFoundException ex) {
            throw new InvalidTokenException("Token bears a non-existent user ID: " + userId, ex);
        }

        if (user == null) {
            // Unlikely to occur, but since this is dependent on the implementation of an interface...
            throw new InvalidTokenException("Found no data for user ID: " + userId, null);
        } else {
            List<? extends GrantedAuthority> authorities = user.getAuthorities();
            if (authorities == null) {
                throw new InvalidTokenException("Invalid token (all scopes have been revoked)", null);
            } else {
                List<String> grantedScopes =
                        authorities.stream()
                                .map(GrantedAuthority::getAuthority).toList();

                checkRequestedScopesAreGranted(grantedScopes);
            }
        }
    }

    protected JwtTokenSignedByThisUAA checkRequestedScopesAreGranted(String... grantedScopes) {
        return checkRequestedScopesAreGranted(Arrays.asList(grantedScopes));
    }

    protected JwtTokenSignedByThisUAA checkRequestedScopesAreGranted(Collection<String> grantedScopes) {
        List<String> requestedScopes = requestedScopes();
        Set<Pattern> grantedScopePatterns = UaaStringUtils.constructWildcards(grantedScopes);
        List<String> missingScopes =
                requestedScopes.stream().filter(
                        requestedScope -> grantedScopePatterns.stream()
                                .noneMatch(grantedScopePattern -> grantedScopePattern.matcher(requestedScope).matches())
                ).toList();
        if (!missingScopes.isEmpty()) {
            String scopeClaimKey = scopeClaimKey().keyName();
            String message =
                    "Some required \"%s\" are missing: [%s]".formatted(
                            scopeClaimKey,
                            String.join(", ", missingScopes));
            throw new InvalidTokenException(message);
        }
        return this;
    }


    public JwtTokenSignedByThisUAA checkClientAndUser(ClientDetails client, UaaUser user) {
        JwtTokenSignedByThisUAA jwtToken =
                checkClient(
                        cid -> {
                            if (!equals(cid, client.getClientId())) {
                                throw new InvalidTokenException("Token's client ID does not match expected value: " + client.getClientId());
                            }
                            return client;
                        });
        if (isUserToken(claims)) {
            return jwtToken
                    .checkUser(uid -> {
                        if (user == null) {
                            throw new InvalidTokenException("Unable to validate user, no user found.");
                        } else {
                            if (!equals(uid, user.getId())) {
                                throw new InvalidTokenException("Token does not have expected user ID.");
                            }
                            return user;
                        }
                    })
                    .checkRequiredUserGroups(
                            ofNullable((Collection<String>) client.getAdditionalInformation().get(REQUIRED_USER_GROUPS)).orElse(emptySet()),
                            AuthorityUtils.authorityListToSet(user.getAuthorities())
                    );

        } else {
            return jwtToken;
        }
    }

    protected JwtTokenSignedByThisUAA checkRequiredUserGroups(Collection<String> requiredGroups, Collection<String> userGroups) {
        if (!UaaTokenUtils.hasRequiredUserGroups(requiredGroups, userGroups)) {
            throw new InvalidTokenException("User does not meet the client's required group criteria.", null);
        }
        return this;
    }

    protected JwtTokenSignedByThisUAA checkClient(Function<String, ClientDetails> getClient) {
        if (!claims.containsKey(CID)) {
            throw new InvalidTokenException("Token bears no client ID.", null);
        }

        if (claims.containsKey(CLIENT_ID) && !equals(claims.get(CID), claims.get(CLIENT_ID))) {
            throw new InvalidTokenException("Token bears conflicting client ID claims.", null);
        }

        String clientId;
        try {
            clientId = (String) claims.get(CID);
        } catch (ClassCastException ex) {
            throw new InvalidTokenException("Token bears an invalid or unparseable CID claim.", ex);
        }

        try {
            ClientDetails client = getClient.apply(clientId);

            Collection<String> clientScopes;
            if (null == claims.get(USER_ID)) {
                // for client credentials tokens, we want to validate the client scopes
                clientScopes = ofNullable(client.getAuthorities())
                        .map(a -> a.stream()
                                .map(GrantedAuthority::getAuthority)
                                .toList())
                        .orElse(Collections.emptyList());
            } else {
                clientScopes = client.getScope();
            }

            checkRequestedScopesAreGranted(clientScopes);
        } catch (NoSuchClientException ex) {
            throw new InvalidTokenException("The token refers to a non-existent client: " + clientId, ex);
        }

        return this;
    }

    public JwtTokenSignedByThisUAA checkRevocationSignature(List<String> revocableSignatureList) {
        if (!claims.containsKey(REVOCATION_SIGNATURE)) {
            // tokens issued before revocation signatures were implemented are still valid
            return this;
        }

        String revocableHashSignature;
        try {
            revocableHashSignature = (String) claims.get(REVOCATION_SIGNATURE);
        } catch (ClassCastException ex) {
            throw new InvalidTokenException("Token bears an invalid or unparseable revocation signature.", ex);
        }

        boolean hashMatched = false;
        for (String revocableSignature : revocableSignatureList) {
            if (revocableHashSignature.equals(revocableSignature)) {
                hashMatched = true;
                break;
            }
        }
        if (revocableHashSignature == null || !hashMatched) {
            throw new TokenRevokedException("revocable signature mismatch");
        }
        return this;
    }

    public JwtTokenSignedByThisUAA checkAudience(String... clients) {
        return checkAudience(Arrays.asList(clients));
    }

    protected JwtTokenSignedByThisUAA checkAudience(Collection<String> clients) {
        if (!claims.containsKey(AUD)) {
            throw new InvalidTokenException("The token does not bear an AUD claim.", null);
        }

        Object audClaim = claims.get(AUD);
        List<String> audience;
        if (audClaim instanceof String string) {
            audience = Collections.singletonList(string);
        } else if (audClaim == null) {
            audience = Collections.emptyList();
        } else {
            try {
                audience = ((List<?>) audClaim).stream()
                        .map(String.class::cast)
                        .toList();
            } catch (ClassCastException ex) {
                throw new InvalidTokenException("The token's audience claim is invalid or unparseable.", ex);
            }
        }

        List<String> notInAudience = clients.stream().filter(c -> !audience.contains(c)).toList();
        if (!notInAudience.isEmpty()) {
            String joinedAudiences = notInAudience.stream().map(c -> "".equals(c) ? "EMPTY_VALUE" : c).collect(Collectors.joining(", "));
            throw new InvalidTokenException("Some parties were not in the token audience: " + joinedAudiences, null);
        }

        return this;
    }

    public JwtTokenSignedByThisUAA checkRevocableTokenStore(RevocableTokenProvisioning revocableTokenProvisioning) {
        try {
            String tokenId;
            if (claims.containsKey(ClaimConstants.REVOCABLE) && (boolean) claims.get(ClaimConstants.REVOCABLE)) {
                if ((tokenId = (String) claims.get(ClaimConstants.JTI)) == null) {
                    throw new InvalidTokenException("The token does not bear a token ID (JTI).", null);
                }
                checkRevocableToken(revocableTokenProvisioning, tokenId);
            }
        } catch (ClassCastException ex) {
            throw new InvalidTokenException("The token's revocability or JTI claim is invalid or unparseable.", ex);
        }

        return this;
    }

    private static void checkRevocableToken(RevocableTokenProvisioning revocableTokenProvisioning, String tokenId) {
        RevocableToken revocableToken = null;
        try {
            revocableToken = revocableTokenProvisioning.retrieve(tokenId, IdentityZoneHolder.get().getId());
        } catch (EmptyResultDataAccessException ignored) {
            // ignore exception until null check below
        }
        if (revocableToken == null) {
            throw new TokenRevokedException("The token has been revoked: " + tokenId);
        }
    }

    private static boolean equals(Object a, Object b) {
        if (a == null) {
            return b == null;
        }
        return a.equals(b);
    }

    private List<String> readScopesFromClaim(ScopeClaimKey scopeClaimKey) {
        String scopeKeyName = scopeClaimKey.keyName();

        if (!claims.containsKey(scopeKeyName)) {
            String errorMessage = "The token does not bear a \"%s\" claim.".formatted(scopeKeyName);
            logger.error(errorMessage);
            throw new InvalidTokenException(errorMessage);
        }

        Object scopeClaim = claims.get(scopeKeyName);
        if (scopeClaim == null) {
            return Lists.newArrayList();
        }

        InvalidTokenException unparsableClaimException = new InvalidTokenException(
                "The token's \"%s\" claim is invalid or unparseable.".formatted(
                        scopeKeyName
                )
        );

        if (!(scopeClaim instanceof List)) {
            throw unparsableClaimException;
        }

        List<?> scopes = (List<?>) scopeClaim;

        if (scopes.stream().allMatch(String.class::isInstance)) {
            return scopes.stream().map(String.class::cast).toList();
        } else {
            throw unparsableClaimException;
        }
    }

    public Jwt getJwt() {
        return tokenJwt;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public JwtTokenSignedByThisUAA checkJti() {
        Object jti = this.getClaims().get(JTI);
        if (jti == null) {
            throw new InvalidTokenException("The token must contain a jti claim.", null);
        }

        validateJtiValue(jti.toString());

        return this;
    }

    protected abstract void validateJtiValue(String jtiValue);

    public ClientDetails getClientDetails(MultitenantClientServices clientDetailsService) {
        String clientId = (String) claims.get(CID);
        try {
            return clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        } catch (NoSuchClientException x) {
            //happens if the client is deleted and token exist
            throw new InvalidTokenException("Invalid client ID " + clientId);
        }
    }

    public UaaUser getUserDetails(UaaUserDatabase userDatabase) {
        String userId = (String) claims.get(USER_ID);
        if (UaaTokenUtils.isUserToken(claims)) {
            try {
                return userDatabase.retrieveUserById(userId);
            } catch (UsernameNotFoundException e) {
                throw new InvalidTokenException("Token bears a non-existent user ID: " + userId);
            }
        }
        return null;
    }

    private static class AccessTokenValidation extends JwtTokenSignedByThisUAA {
        public AccessTokenValidation(String tokenJwtValue, KeyInfoService keyInfoService) {
            super(tokenJwtValue, keyInfoService);
        }

        @Override
        protected void validateJtiValue(String jtiValue) {
            if (jtiValue.endsWith(REFRESH_TOKEN_SUFFIX)) {
                throw new InvalidTokenException("Invalid access token.", null);
            }
        }

        @Override
        ScopeClaimKey scopeClaimKey() {
            return ScopeClaimKey.SCOPE;
        }
    }

    private static class RefreshTokenValidation extends JwtTokenSignedByThisUAA {
        public RefreshTokenValidation(String tokenJwtValue, KeyInfoService uaaUrl) {
            super(tokenJwtValue, uaaUrl);
        }

        @Override
        protected void validateJtiValue(String jtiValue) {
            if (!jtiValue.endsWith(REFRESH_TOKEN_SUFFIX)) {
                throw new InvalidTokenException("Invalid refresh token.", null);
            }
        }

        @Override
        ScopeClaimKey scopeClaimKey() {
            if (this.getClaims().containsKey(ScopeClaimKey.GRANTED_SCOPES.keyName())) {
                return ScopeClaimKey.GRANTED_SCOPES;
            }
            return ScopeClaimKey.SCOPE;
        }
    }

    private static class IdTokenValidation extends JwtTokenSignedByThisUAA {
        public IdTokenValidation(String tokenJwtValue, KeyInfoService keyInfoService) {
            super(tokenJwtValue, keyInfoService);
        }

        @Override
        ScopeClaimKey scopeClaimKey() {
            return ScopeClaimKey.SCOPE;
        }

        @Override
        protected void validateJtiValue(String jtiValue) {
            if (jtiValue.endsWith(REFRESH_TOKEN_SUFFIX)) {
                throw new InvalidTokenException("Invalid access token.", null);
            }
        }
    }

    enum ScopeClaimKey {
        SCOPE(ClaimConstants.SCOPE),
        GRANTED_SCOPES(ClaimConstants.GRANTED_SCOPES);

        private String keyName;

        ScopeClaimKey(String keyName) {
            this.keyName = keyName;
        }

        String keyName() {
            return this.keyName;
        }
    }
}
