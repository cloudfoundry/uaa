/*******************************************************************************
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

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.TokenRevokedException;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.flywaydb.core.internal.util.StringUtils;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXP;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANTED_SCOPES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.REVOCATION_SIGNATURE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SCOPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REFRESH_TOKEN_SUFFIX;
import static org.cloudfoundry.identity.uaa.util.UaaTokenUtils.isUserToken;

public class TokenValidation {
    private static final Log logger = LogFactory.getLog(TokenValidation.class);
    private final Map<String, Object> claims;
    private final Jwt tokenJwt;
    private final String token;
    private final boolean decoded; // this is used to avoid checking claims on tokens that had errors when decoding
    private final List<RuntimeException> validationErrors = new ArrayList<>();
    private boolean isAccessToken;

    public static TokenValidation buildAccessTokenValidator(String tokenJwtValue) {
        return new TokenValidation(tokenJwtValue, true);
    }

    public static TokenValidation buildRefreshTokenValidator(String tokenJwtValue) {
        return new TokenValidation(tokenJwtValue, false);
    }

    private TokenValidation(String token, boolean isAccessToken) {
        this.token = token;
        this.isAccessToken = isAccessToken;

        Jwt tokenJwt;
        try {
            tokenJwt = JwtHelper.decode(token);
        } catch (Exception ex) {
            tokenJwt = null;
            validationErrors.add(new InvalidTokenException("Invalid token (could not decode): " + token, ex));
        }
        this.tokenJwt = tokenJwt;

        String tokenJwtClaims;
        if(tokenJwt != null && StringUtils.hasText(tokenJwtClaims = tokenJwt.getClaims())) {
            Map<String, Object> claims;
            try {
                claims = JsonUtils.readValue(tokenJwtClaims, new TypeReference<Map<String, Object>>() {});
            }
            catch (JsonUtils.JsonUtilException ex) {
                claims = null;
                validationErrors.add(new InvalidTokenException("Invalid token (cannot read token claims): " + token, ex));
            }
            this.claims = claims;
        } else {
            this.claims = new HashMap<>();
        }

        if (tokenJwt != null) {
            validateHeader(tokenJwt);
        }

        this.decoded = isValid();
    }

    private TokenValidation validateHeader(Jwt tokenJwt) {
        String kid = tokenJwt.getHeader().getKid();
        if (kid == null) {
            validationErrors.add(
                new InvalidTokenException("kid claim not found in JWT token header")
            );
            return this;
        }

        KeyInfo signingKey = KeyInfo.getKey(kid);
        if (signingKey == null) {
            validationErrors.add(
                new InvalidTokenException(String.format(
                    "Token header claim [kid] references unknown signing key : [%s]", kid
                ))
            );
            return this;
        }

        SignatureVerifier signatureVerifier = signingKey.getVerifier();
        return checkSignature(signatureVerifier);
    }

    public boolean isValid() {
        return validationErrors.size() == 0;
    }


    public List<RuntimeException> getValidationErrors() {
        return validationErrors;
    }

    @SuppressWarnings("CloneDoesntCallSuperClone")
    public TokenValidation clone() {
        return new TokenValidation(this);
    }


    private TokenValidation(TokenValidation source) {
        this.claims = source.claims == null ? null : new HashMap<>(source.claims);
        this.tokenJwt = source.tokenJwt;
        this.token = source.token;
        this.decoded = source.decoded;
        this.scopes = source.scopes;
    }


    public TokenValidation checkSignature(SignatureVerifier verifier) {
        if(!decoded) { return this; }
        try {
            tokenJwt.verifySignature(verifier);
        } catch (Exception ex) {
            logger.debug("Invalid token (could not verify signature)", ex);
            addError("Could not verify token signature.", new InvalidSignatureException(token));
        }
        return this;
    }

    public TokenValidation checkIssuer(String issuer) {
        if(issuer == null) { return this; }

        if(!decoded || !claims.containsKey(ISS)) {
            addError("Token does not bear an ISS claim.");
            return this;
        }

        if(!equals(issuer, claims.get(ISS))) {
            addError("Invalid issuer (" + claims.get(ISS) + ") for token did not match expected: " + issuer);
        }
        return this;
    }

    protected TokenValidation checkExpiry(Instant asOf) {
        if(!decoded || !claims.containsKey(EXP)) {
            addError("Token does not bear an EXP claim.");
            return this;
        }

        Object expClaim = claims.get(EXP);
        long expiry;
        try {
            expiry = (int) expClaim;
            if(asOf.getEpochSecond() > expiry) { addError("Token expired at " + expiry); }
        } catch (ClassCastException ex) {
            addError("Token bears an invalid or unparseable EXP claim.", ex);
        }
        return this;
    }

    public TokenValidation checkExpiry() {
        return checkExpiry(Instant.now());
    }

    protected TokenValidation checkUser(Function<String, UaaUser> getUser) {
        if(!decoded || !isUserToken(claims)) {
            addError("Token is not a user token.");
            return this;
        }

        if(!claims.containsKey(USER_ID)) {
            addError("Token does not bear a USER_ID claim.");
            return this;
        }

        String userId;
        Object userIdClaim = claims.get(USER_ID);
        try {
            userId = (String) userIdClaim;
        } catch (ClassCastException ex) {
            addError("Token bears an invalid or unparseable USER_ID claim.", ex);
            return this;
        }

        if(userId == null) {
            addError("Token has a null USER_ID claim.");
        }
        else {
            UaaUser user;
            try {
                user = getUser.apply(userId);
                Assert.notNull(user);
            } catch (UsernameNotFoundException ex) {
                user = null;
                addError("Token bears a non-existent user ID: " + userId, ex);
            } catch(InvalidTokenException ex) {
                user = null;
                validationErrors.add(ex);
            }

            if(user == null) {
                // Unlikely to occur, but since this is dependent on the implementation of an interface...
                addError("Found no data for user ID: " + userId);
            } else {
                List<? extends GrantedAuthority> authorities = user.getAuthorities();
                if (authorities == null) {
                    addError("Invalid token (all scopes have been revoked)");
                } else {
                    List<String> authoritiesValue = authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
                    checkScopesWithin(authoritiesValue);
                }
            }
        }
        return this;
    }

    protected TokenValidation checkScopesWithin(String... scopes) {
        return checkScopesWithin(Arrays.asList(scopes));
    }

    protected TokenValidation checkScopesWithin(Collection<String> scopes) {
        getScopes().ifPresent(tokenScopes -> {
            Set<Pattern> scopePatterns = UaaStringUtils.constructWildcards(scopes);
            List<String> missingScopes = tokenScopes.stream().filter(s -> !scopePatterns.stream().anyMatch(p -> p.matcher(s).matches())).collect(Collectors.toList());
            if(!missingScopes.isEmpty()) {
                String claimName = isAccessToken ? SCOPE : GRANTED_SCOPES;
                String message = String.format("Some required %s are missing: " + missingScopes.stream().collect(Collectors.joining(" ")), claimName);
                validationErrors.add(new InsufficientScopeException(message));
            }
        });
        return this;
    }

    public TokenValidation checkClientAndUser(ClientDetails client, UaaUser user) {
        TokenValidation validation =
            checkClient(
                cid -> {
                    if (!equals(cid, client.getClientId())) {
                        throw new InvalidTokenException("Token's client ID does not match expected value: " + client.getClientId());
                    }
                    return client;
                });
        if (isUserToken(claims)) {
            return validation
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
            return validation;
        }
    }

    protected TokenValidation checkRequiredUserGroups(Collection<String> requiredGroups, Collection<String> userGroups) {
        if (!UaaTokenUtils.hasRequiredUserGroups(requiredGroups, userGroups)) {
            addError("User does not meet the client's required group criteria.");
        }
        return this;
    }

    protected TokenValidation checkClient(Function<String, ClientDetails> getClient) {
        if(!decoded || !claims.containsKey(CID)) {
            addError("Token bears no client ID.");
            return this;
        }

        if(claims.containsKey(CLIENT_ID) && !equals(claims.get(CID), claims.get(CLIENT_ID))) {
            addError("Token bears conflicting client ID claims.");
            return this;
        }

        String clientId;
        try {
            clientId = (String) claims.get(CID);
        } catch (ClassCastException ex) {
            addError("Token bears an invalid or unparseable CID claim.", ex);
            return this;
        }

        try {
            ClientDetails client = getClient.apply(clientId);

            Collection<String> clientScopes;
            if (null == claims.get(USER_ID)) {
                // for client credentials tokens, we want to validate the client scopes
                clientScopes = ofNullable(client.getAuthorities())
                    .map(a -> a.stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                    .orElse(Collections.emptyList());
            } else {
                clientScopes = client.getScope();
            }

            checkScopesWithin(clientScopes);
        } catch(NoSuchClientException ex) {
            addError("The token refers to a non-existent client: " + clientId, ex);
        } catch(InvalidTokenException ex) {
            validationErrors.add(ex);
        }

        return this;
    }

    public TokenValidation checkRevocationSignature(List<String> revocableSignatureList) {
        if(!decoded) {
            addError("Token does not bear a revocation hash.");
            return this;
        }
        if(!claims.containsKey(REVOCATION_SIGNATURE)) {
            // tokens issued before revocation signatures were implemented are still valid
            return this;
        }

        String revocableHashSignature;
        try {
            revocableHashSignature = (String)claims.get(REVOCATION_SIGNATURE);
        } catch (ClassCastException ex) {
            addError("Token bears an invalid or unparseable revocation signature.", ex);
            return this;
        }

        boolean hashMatched = false;
        for (String revocableSignature : revocableSignatureList) {
            if(revocableHashSignature.equals(revocableSignature)){
                hashMatched = true;
                break;
            }
        }
        if(revocableHashSignature == null || !hashMatched) {
            validationErrors.add(new TokenRevokedException("revocable signature mismatch"));
        }
        return this;
    }

    public TokenValidation checkAudience(String... clients) {
        return checkAudience(Arrays.asList(clients));
    }

    protected TokenValidation checkAudience(Collection<String> clients) {
        if (!decoded || !claims.containsKey(AUD)) {
            addError("The token does not bear an AUD claim.");
            return this;
        }

        Object audClaim = claims.get(AUD);
        List<String> audience;
        if(audClaim instanceof String) {
            audience = Collections.singletonList((String) audClaim);
        }
        else if(audClaim == null) {
            audience = Collections.emptyList();
        }
        else {
            try {
                audience = ((List<?>) audClaim).stream()
                        .map(s -> (String) s)
                        .collect(Collectors.toList());
            } catch (ClassCastException ex) {
                addError("The token's audience claim is invalid or unparseable.", ex);
                return this;
            }
        }

        List<String> notInAudience = clients.stream().filter(c -> !audience.contains(c)).collect(Collectors.toList());
        if(!notInAudience.isEmpty()) {
            String joinedAudiences = notInAudience.stream().map(c ->  "".equals(c) ? "EMPTY_VALUE" : c  ).collect(Collectors.joining(", "));
            addError("Some parties were not in the token audience: " + joinedAudiences);
        }

        return this;
    }

    public TokenValidation checkRevocableTokenStore(RevocableTokenProvisioning revocableTokenProvisioning) {
        if(!decoded) {
            addError("The token could not be checked for revocation.");
            return this;
        }

        try {
            String tokenId;
            if(claims.containsKey(ClaimConstants.REVOCABLE) && (boolean) claims.get(ClaimConstants.REVOCABLE)) {
                if((tokenId = (String) claims.get(ClaimConstants.JTI)) == null) {
                    addError("The token does not bear a token ID (JTI).");
                    return this;
                }

                RevocableToken revocableToken = null;
                try {
                    revocableToken = revocableTokenProvisioning.retrieve(tokenId, IdentityZoneHolder.get().getId());
                } catch(EmptyResultDataAccessException ex) {
                }

                if(revocableToken == null) {
                    validationErrors.add(new TokenRevokedException("The token has been revoked: " + tokenId));
                }
            }
        } catch(ClassCastException ex) {
            addError("The token's revocability or JTI claim is invalid or unparseable.", ex);
            return this;
        }

        return this;
    }

    private boolean addError(String msg, Exception cause) {
        return validationErrors.add(new InvalidTokenException(msg, cause));
    }

    private boolean addError(String msg) {
        return addError(msg, null);
    }

    private static boolean equals(Object a, Object b) {
        if(a == null) return b == null;
        return a.equals(b);
    }

    private Optional<List<String>> scopes = null;
    private Optional<List<String>> getScopes() {
        return isAccessToken ? readScopesFromClaim(SCOPE) : readScopesFromClaim(GRANTED_SCOPES);
    }

    private Optional<List<String>> readScopesFromClaim(String claimName) {
        if (!decoded || !claims.containsKey(claimName)) {
            addError(
                String.format("The token does not bear a %s claim.", claimName)
            );
            return scopes = Optional.empty();
        }

        Object scopeClaim = claims.get(claimName);
        if (scopeClaim == null) {
            // treat null scope claim the same as empty scope claim
            scopeClaim = new ArrayList<>();
        }

        try {
            return scopes = Optional.of(((List<?>) scopeClaim).stream()
                .map(s -> (String) s)
                .collect(Collectors.toList()));
        } catch (ClassCastException ex) {
            addError("The token's scope claim is invalid or unparseable.", ex);
            return scopes = Optional.empty();
        }
    }

    public TokenValidation throwIfInvalid() {
        if(!isValid()) {
            throw validationErrors.get(0);
        }
        return this;
    }

    public Jwt getJwt() {
        return tokenJwt;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public TokenValidation checkAccessToken() {
        Object jti = this.getClaims().get(JTI);
        if (jti == null) {
            addError("The token must contain a jti claim.");
            return this;
        }

        if (jti.toString().endsWith(REFRESH_TOKEN_SUFFIX)) {
            addError("Invalid access token.");
        }

        return this;
    }

    public ClientDetails getClientDetails(ClientServicesExtension clientDetailsService) {
        String clientId = (String) claims.get(CID);
        try {
            return clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        } catch (NoSuchClientException x) {
            //happens if the client is deleted and token exist
            throw new InvalidTokenException("Invalid client ID "+clientId);
        }
    }

    public UaaUser getUserDetails(UaaUserDatabase userDatabase) {
        String userId = (String) claims.get(USER_ID);
        if( UaaTokenUtils.isUserToken(claims)) {
            try {
                return userDatabase.retrieveUserById(userId);
            } catch (UsernameNotFoundException e) {
                throw new InvalidTokenException("Token bears a non-existent user ID: " + userId);
            }
        }
        return null;
    }
}
