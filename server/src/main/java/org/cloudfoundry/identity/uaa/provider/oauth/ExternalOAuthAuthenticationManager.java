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

package org.cloudfoundry.identity.uaa.provider.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ObjectUtils;
import org.cloudfoundry.identity.uaa.authentication.AbstractClientParametersAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.ProviderConfigurationException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeyHelper;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.oauth.jwt.ChainedSignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.jwt.SignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.UaaMacSigner;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode;
import org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA;
import org.cloudfoundry.identity.uaa.util.LinkedMaskingMultiValueMap;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static java.util.Objects.isNull;
import static java.util.stream.Collectors.toSet;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.CompositeToken.ID_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.EXPLICITLY_MAPPED;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_VERIFIED_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA.buildIdTokenValidator;
import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.isAcceptedInvitationAuthentication;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.retainAllMatches;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.util.StringUtils.hasLength;
import static org.springframework.util.StringUtils.hasText;

@Slf4j
public class ExternalOAuthAuthenticationManager extends ExternalLoginAuthenticationManager<ExternalOAuthAuthenticationManager.AuthenticationData> {

    private final RestTemplate trustingRestTemplate;
    private final RestTemplate nonTrustingRestTemplate;
    private final OidcMetadataFetcher oidcMetadataFetcher;
    private final TokenEndpointBuilder tokenEndpointBuilder;
    @Getter
    private final KeyInfoService keyInfoService;
    private final IdentityZoneManager identityZoneManager;

    //origin is per thread during execution
    private final ThreadLocal<String> origin = ThreadLocal.withInitial(() -> "unknown");

    public ExternalOAuthAuthenticationManager(
            IdentityProviderProvisioning providerProvisioning,
            IdentityZoneManager identityZoneManager,
            RestTemplate trustingRestTemplate,
            RestTemplate nonTrustingRestTemplate,
            TokenEndpointBuilder tokenEndpointBuilder,
            KeyInfoService keyInfoService,
            OidcMetadataFetcher oidcMetadataFetcher
    ) {
        super(providerProvisioning);
        this.identityZoneManager = identityZoneManager;
        this.trustingRestTemplate = trustingRestTemplate;
        this.nonTrustingRestTemplate = nonTrustingRestTemplate;
        this.tokenEndpointBuilder = tokenEndpointBuilder;
        this.keyInfoService = keyInfoService;
        this.oidcMetadataFetcher = oidcMetadataFetcher;
    }

    @Override
    public String getOrigin() {
        //origin is per thread during execution
        return origin.get();
    }

    @Override
    public void setOrigin(String origin) {
        this.origin.set(origin);
    }

    public IdentityProvider resolveOriginProvider(String idToken) throws AuthenticationException {
        try {
            Map<String, Object> claims = parseClaimsFromIdTokenString(idToken);
            String issuer = (String) claims.get(ClaimConstants.ISS);
            if (!hasLength(issuer)) {
                throw new InsufficientAuthenticationException("Issuer is missing in id_token");
            }
            //1. Check if issuer is registered provider
            try {
                return retrieveRegisteredIdentityProviderByIssuer(issuer);
            } catch (IncorrectResultSizeDataAccessException x) {
                logger.debug("No registered identity provider found for given issuer. Checking for uaa.");
            }
            //2. If not, check if issuer is self
            if (idTokenWasIssuedByTheUaa(issuer)) {
                //3. If yes, handle origin correctly
                String originKey = (String) claims.get(ClaimConstants.ORIGIN);
                if (hasLength(originKey)) {
                    return buildInternalUaaIdpConfig(issuer, originKey);
                }
            }
            //All other cases: throw Exception
            throw new InsufficientAuthenticationException("Unable to map issuer, %s , to a single registered provider".formatted(issuer));
        } catch (IllegalArgumentException | JsonUtils.JsonUtilException x) {
            throw new InsufficientAuthenticationException("Unable to decode expected id_token");
        }
    }

    public IdentityProvider retrieveRegisteredIdentityProviderByIssuer(String issuer) {
        return ((ExternalOAuthProviderConfigurator) getProviderProvisioning()).retrieveByIssuer(issuer, identityZoneManager.getCurrentIdentityZoneId());
    }

    private Map<String, Object> parseClaimsFromIdTokenString(String idToken) {
        String claimsString = JwtHelper.decode(Optional.ofNullable(idToken).orElse("")).getClaims();
        return JsonUtils.readValue(claimsString, new TypeReference<>() {
        });
    }

    public boolean idTokenWasIssuedByTheUaa(String issuer) {
        return issuer.equals(tokenEndpointBuilder.getTokenEndpoint(identityZoneManager.getCurrentIdentityZone()));
    }

    private IdentityProvider buildInternalUaaIdpConfig(String issuer, String originKey) {
        OIDCIdentityProviderDefinition uaaOidcProviderConfig = new OIDCIdentityProviderDefinition();
        uaaOidcProviderConfig.setIssuer(issuer);
        Map<String, Object> userNameMapping = singletonMap(USER_NAME_ATTRIBUTE_NAME, USER_NAME_ATTRIBUTE_NAME);
        uaaOidcProviderConfig.setAttributeMappings(userNameMapping);
        IdentityProvider<OIDCIdentityProviderDefinition> uaaIdp = new IdentityProvider<>();
        uaaIdp.setOriginKey(originKey);
        uaaIdp.setConfig(uaaOidcProviderConfig);
        return uaaIdp;
    }

    @Override
    protected AuthenticationData getExternalAuthenticationDetails(final Authentication authentication) {
        final ExternalOAuthCodeToken codeToken = (ExternalOAuthCodeToken) authentication;

        IdentityProvider provider = null;
        if (!hasLength(codeToken.getOrigin())) {
            provider = resolveOriginProvider(codeToken.getIdToken());
            codeToken.setOrigin(provider.getOriginKey());
        }

        setOrigin(codeToken.getOrigin());
        if (provider == null) {
            try {
                provider = getProviderProvisioning().retrieveByOrigin(getOrigin(), identityZoneManager.getCurrentIdentityZoneId());
            } catch (EmptyResultDataAccessException e) {
                logger.info("No provider found for given origin");
                throw new InsufficientAuthenticationException("Could not resolve identity provider with given origin.");
            }
        }

        if (provider != null && provider.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition config) {
            final AuthenticationData authenticationData = new AuthenticationData();

            final Map<String, Object> claims = getClaimsFromToken(codeToken, provider);

            if (claims == null) {
                return null;
            }
            authenticationData.setClaims(claims);

            final Map<String, Object> attributeMappings = config.getAttributeMappings();

            final String userNameAttributePrefix = (String) attributeMappings.get(USER_NAME_ATTRIBUTE_NAME);
            final String username;
            if (hasText(userNameAttributePrefix)) {
                username = getMappedClaim(userNameAttributePrefix, USER_NAME_ATTRIBUTE_NAME, claims);
                logger.debug("Extracted username for claim: {} and username is: {}", userNameAttributePrefix, username);
            } else {
                username = getMappedClaim(null, SUB, claims);
                logger.debug("Extracted username for claim: {} and username is: {}", SUB, username);
            }
            if (!hasText(username)) {
                throw new InsufficientAuthenticationException("Unable to map claim to a username");
            }

            authenticationData.setUsername(username);

            List<SimpleGrantedAuthority> oidcAuthorities = extractExternalOAuthUserAuthorities(attributeMappings, claims);
            oidcAuthorities = filterOidcAuthorities(config, oidcAuthorities);

            final OAuthGroupMappingMode groupMappingMode = Optional.ofNullable(config.getGroupMappingMode())
                    .orElse(EXPLICITLY_MAPPED);

            final List<SimpleGrantedAuthority> authorities;
            switch (groupMappingMode) {
                case AS_SCOPES:
                    authorities = new LinkedList<>(oidcAuthorities);
                    break;
                case EXPLICITLY_MAPPED:
                default:
                    authorities = mapAuthorities(codeToken.getOrigin(), oidcAuthorities);
                    break;
            }
            authenticationData.setAuthorities(authorities); //the filter should apply to external authorities - not internal
            authenticationData.setExternalAuthorities(oidcAuthorities);
            Optional.ofNullable(attributeMappings).ifPresent(map -> authenticationData.setAttributeMappings(new HashMap<>(map)));
            return authenticationData;
        }
        logger.debug("No identity provider found for origin:{} and zone:{}", getOrigin(), identityZoneManager.getCurrentIdentityZoneId());
        return null;
    }

    private static List<? extends GrantedAuthority> filterOidcAuthorities(AbstractExternalOAuthIdentityProviderDefinition<? extends ExternalIdentityProviderDefinition> definition, List<? extends GrantedAuthority> oidcAuthorities) {
        List<String> whiteList = Optional.of(definition.getExternalGroupsWhitelist()).orElse(emptyList());
        if (whiteList.isEmpty()) {
            return oidcAuthorities;
        } else {
            Set<String> authorities = oidcAuthorities.stream().map(GrantedAuthority::getAuthority).collect(toSet());
            Set<String> result = retainAllMatches(authorities, whiteList);
            if (ObjectUtils.isNotEmpty(result)) {
                log.debug("White listed external OIDC groups:'{}'", result);
            }
            return result.stream().map(SimpleGrantedAuthority::new).toList();
        }
    }

    @Override
    protected void populateAuthenticationAttributes(UaaAuthentication authentication, Authentication request, AuthenticationData authenticationData) {
        Map<String, Object> claims = authenticationData.getClaims();
        if (claims != null) {
            if (claims.get("amr") != null) {
                final Collection<String> amrClaims = (Collection<String>) claims.get("amr");
                if (authentication.getAuthenticationMethods() == null) {
                    authentication.setAuthenticationMethods(new HashSet<>(amrClaims));
                } else {
                    authentication.getAuthenticationMethods().addAll(amrClaims);
                }
            }

            Object acr = claims.get(ClaimConstants.ACR);
            if (acr != null) {
                if (acr instanceof Map acrMap) {
                    Object values = acrMap.get("values");
                    if (values instanceof Collection collection) {
                        authentication.setAuthContextClassRef(new HashSet<>(collection));
                    } else if (values instanceof String[] strings) {
                        authentication.setAuthContextClassRef(new HashSet<>(Arrays.asList(strings)));
                    } else {
                        log.debug("Unrecognized ACR claim[{}] for user_id: {}", values, authentication.getPrincipal().getId());
                    }
                } else if (acr instanceof String string) {
                    authentication.setAuthContextClassRef(new HashSet(singletonList(string)));
                } else {
                    log.debug("Unrecognized ACR claim[{}] for user_id: {}", acr, authentication.getPrincipal().getId());
                }
            }
            MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
            log.debug("Mapping ExternalOAuth custom attributes");
            for (Map.Entry<String, Object> entry : authenticationData.getAttributeMappings().entrySet()) {
                if (entry.getKey().startsWith(USER_ATTRIBUTE_PREFIX) && entry.getValue() != null) {
                    String key = entry.getKey().substring(USER_ATTRIBUTE_PREFIX.length());
                    Object values = claims.get(entry.getValue());
                    if (values != null) {
                        log.debug("Mapped ExternalOAuth attribute {} to {}", key, values);
                        if (values instanceof List list) {
                            List<String> strings = list.stream()
                                    .map(object -> Objects.toString(object, null))
                                    .toList();
                            userAttributes.put(key, strings);
                        } else if (values instanceof String string) {
                            userAttributes.put(key, singletonList(string));
                        } else {
                            userAttributes.put(key, singletonList(values.toString()));
                        }
                    }
                }
            }
            authentication.setUserAttributes(userAttributes);
            authentication.setExternalGroups(
                    Optional.ofNullable(authenticationData.getExternalAuthorities())
                            .orElse(emptyList())
                            .stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(toSet())
            );
        }
        if (authentication.getAuthenticationMethods() == null) {
            authentication.setAuthenticationMethods(new HashSet<>());
        }
        authentication.getAuthenticationMethods().add("oauth");
        ExternalOAuthCodeToken externalOAuthCodeToken = (ExternalOAuthCodeToken) request;
        if (externalOAuthCodeToken.getIdToken() != null) {
            authentication.setIdpIdToken(externalOAuthCodeToken.getIdToken());
        }
        super.populateAuthenticationAttributes(authentication, request, authenticationData);
    }

    @Override
    protected List<String> getExternalUserAuthorities(UserDetails request) {
        return super.getExternalUserAuthorities(request);
    }

    @Override
    protected UaaUser getUser(Authentication request, AuthenticationData authenticationData) {
        if (authenticationData != null) {

            String emailClaim = (String) authenticationData.getAttributeMappings().get(EMAIL_ATTRIBUTE_NAME);
            String givenNameClaim = (String) authenticationData.getAttributeMappings().get(GIVEN_NAME_ATTRIBUTE_NAME);
            String familyNameClaim = (String) authenticationData.getAttributeMappings().get(FAMILY_NAME_ATTRIBUTE_NAME);
            String phoneClaim = (String) authenticationData.getAttributeMappings().get(PHONE_NUMBER_ATTRIBUTE_NAME);
            Object emailVerifiedClaim = authenticationData.getAttributeMappings().get(EMAIL_VERIFIED_ATTRIBUTE_NAME);

            Map<String, Object> claims = authenticationData.getClaims();

            String username = authenticationData.getUsername();
            String givenName = getMappedClaim(givenNameClaim, "given_name", claims);
            String familyName = getMappedClaim(familyNameClaim, "family_name", claims);
            String phoneNumber = getMappedClaim(phoneClaim, "phone_number", claims);
            String email = getMappedClaim(emailClaim, "email", claims);
            Object verifiedObj = claims.get(emailVerifiedClaim == null ? "email_verified" : emailVerifiedClaim);
            boolean verified = verifiedObj instanceof Boolean b ? b : false;

            if (!StringUtils.hasText(email)) {
                email = generateEmailIfNullOrEmpty(username);
            }

            log.debug("Returning user data for username:{}, email:{}", username, email);

            return new UaaUser(
                    new UaaUserPrototype()
                            .withEmail(email)
                            .withGivenName(givenName)
                            .withFamilyName(familyName)
                            .withPhoneNumber(phoneNumber)
                            .withModified(new Date())
                            .withUsername(username)
                            .withPassword("")
                            .withAuthorities(authenticationData.getAuthorities())
                            .withCreated(new Date())
                            .withOrigin(getOrigin())
                            .withExternalId((String) authenticationData.getClaims().get(SUB))
                            .withVerified(verified)
                            .withZoneId(identityZoneManager.getCurrentIdentityZoneId())
                            .withSalt(null)
                            .withPasswordLastModified(null));
        }
        log.debug("Authenticate data is missing, unable to return user");
        return null;
    }

    private String getMappedClaim(String externalName, String internalName, Map<String, Object> claims) {
        String claimName = isNull(externalName) ? internalName : externalName;
        Object claimObject = claims.get(claimName);

        if (isNull(claimObject)) {
            return null;
        }
        if (claimObject instanceof String string) {
            return string;
        }
        if (claimObject instanceof Collection<?> collection) {
            Set<String> entry = collection.stream().filter(String.class::isInstance).map(String.class::cast).collect(toSet());
            if (entry.size() == 1) {
                return entry.stream().findFirst().orElse(null);
            } else if (entry.isEmpty()) {
                return null;
            } else {
                log.warn("Claim mapping for {} attribute is ambiguous. ({}) ", claimName, entry.size());
                throw new BadCredentialsException("Claim mapping for " + internalName + " attribute is ambiguous");
            }
        }
        log.warn("Claim attribute {} cannot be mapped because of invalid type {} ", claimName, claimObject.getClass().getSimpleName());
        throw new BadCredentialsException("External token attribute " + claimName + " cannot be mapped to user attribute " + internalName);
    }

    private List<SimpleGrantedAuthority> extractExternalOAuthUserAuthorities(Map<String, Object> attributeMappings, Map<String, Object> claims) {
        List<String> groupNames = new LinkedList<>();
        if (attributeMappings.get(GROUP_ATTRIBUTE_NAME) instanceof String string) {
            groupNames.add(string);
        } else if (attributeMappings.get(GROUP_ATTRIBUTE_NAME) instanceof Collection collection) {
            groupNames.addAll(collection);
        }
        log.debug("Extracting ExternalOAuth group names:{}", groupNames);

        Set<String> scopes = new HashSet<>();
        for (String g : groupNames) {
            Object roles = claims.get(g);
            if (roles instanceof String string) {
                scopes.addAll(Arrays.asList(string.split(",")));
            } else if (roles instanceof Collection collection) {
                scopes.addAll(collection);
            }
        }

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (String scope : scopes) {
            authorities.add(new SimpleGrantedAuthority(scope));
        }

        return authorities;
    }

    @Override
    protected UaaUser userAuthenticated(Authentication request, UaaUser userFromRequest, UaaUser userFromDb) {
        boolean userModified = false;
        boolean isInvitationAcceptance = isAcceptedInvitationAuthentication();
        String email = userFromRequest.getEmail();
        log.debug("ExternalOAuth user authenticated:{}", email);
        if (isInvitationAcceptance) {
            String invitedUserId = (String) RequestContextHolder.currentRequestAttributes().getAttribute("user_id", RequestAttributes.SCOPE_SESSION);
            log.debug("ExternalOAuth user accepted invitation, user_id:{}", invitedUserId);
            userFromDb = new UaaUser(getUserDatabase().retrieveUserPrototypeById(invitedUserId));
            if (email != null && !email.equalsIgnoreCase(userFromDb.getEmail())) {
                throw new BadCredentialsException("OAuth User email mismatch. Authenticated email doesn't match invited email.");
            }

            publish(new InvitedUserAuthenticatedEvent(userFromDb));
            userFromDb = new UaaUser(getUserDatabase().retrieveUserPrototypeById(invitedUserId));
        }

        boolean isRegisteredIdpAuthentication = isRegisteredIdpAuthentication(request);

        //we must check and see if the email address has changed between authentications
        if (haveUserAttributesChanged(userFromDb, userFromRequest) && isRegisteredIdpAuthentication) {
            log.debug("User attributed have changed, updating them.");
            userFromDb = userFromDb.modifyAttributes(email,
                            userFromRequest.getGivenName(),
                            userFromRequest.getFamilyName(),
                            userFromRequest.getPhoneNumber(),
                            userFromRequest.getExternalId(),
                            userFromDb.isVerified() || userFromRequest.isVerified())
                    .modifyUsername(userFromRequest.getUsername());
            userModified = true;
        }

        if (isRegisteredIdpAuthentication) {
            ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(userFromDb, userModified, userFromRequest.getAuthorities(), true);
            publish(event);
        }
        return getUserDatabase().retrieveUserById(userFromDb.getId());
    }

    private boolean isRegisteredIdpAuthentication(Authentication request) {
        String idToken = ((ExternalOAuthCodeToken) request).getIdToken();
        if (idToken == null) {
            return true;
        }
        Map<String, Object> claims = parseClaimsFromIdTokenString(idToken);
        String issuer = (String) claims.get(ClaimConstants.ISS);
        if (idTokenWasIssuedByTheUaa(issuer)) {
            try {
                // check if the UAA Identity Zone is registered as an external Idp of itself
                retrieveRegisteredIdentityProviderByIssuer(issuer);
                return true;
            } catch (IncorrectResultSizeDataAccessException e) {
                return false;
            }
        } else {
            return true;
        }
    }

    @Override
    protected boolean isAddNewShadowUser() {
        if (!super.isAddNewShadowUser()) {
            return false;
        }
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> provider = getProviderProvisioning().retrieveByOrigin(getOrigin(), identityZoneManager.getCurrentIdentityZoneId());
        return provider.getConfig().isAddShadowUserOnLogin();
    }

    public RestTemplate getRestTemplate(AbstractExternalOAuthIdentityProviderDefinition config) {
        if (config.isSkipSslValidation()) {
            return trustingRestTemplate;
        } else {
            return nonTrustingRestTemplate;
        }
    }

    protected String getResponseType(AbstractExternalOAuthIdentityProviderDefinition config) {
        if (RawExternalOAuthIdentityProviderDefinition.class.isAssignableFrom(config.getClass())) {
            if ("signed_request".equals(config.getResponseType())) {
                return "signed_request";
            } else if ("code".equals(config.getResponseType())) {
                return "code";
            } else {
                return "token";
            }
        } else if (OIDCIdentityProviderDefinition.class.isAssignableFrom(config.getClass())) {
            return ID_TOKEN;
        } else {
            throw new IllegalArgumentException("Unknown type for provider.");
        }
    }

    protected <T extends AbstractExternalOAuthIdentityProviderDefinition<T>> Map<String, Object> getClaimsFromToken(
            ExternalOAuthCodeToken codeToken,
            final IdentityProvider<T> identityProvider
    ) {
        String idToken = getTokenFromCode(codeToken, identityProvider);
        codeToken.setIdToken(idToken);
        return getClaimsFromToken(idToken, identityProvider);
    }

    protected <T extends AbstractExternalOAuthIdentityProviderDefinition<T>> Map<String, Object> getClaimsFromToken(
            String idToken,
            final IdentityProvider<T> identityProvider
    ) {
        log.debug("Extracting claims from id_token");
        if (idToken == null) {
            log.debug("id_token is null, no claims returned.");
            return null;
        }

        final T config = identityProvider.getConfig();

        if ("signed_request".equals(config.getResponseType())) {
            String secret = config.getRelyingPartySecret();
            if (log.isDebugEnabled()) {
                log.debug("Validating signed_request: {}", UaaStringUtils.getCleanedUserControlString(idToken));
            }
            //split request into signature and data
            String[] signedRequests = idToken.split("\\.", 2);
            //parse signature
            String signature = signedRequests[0];
            //parse data and convert to json object
            String data = signedRequests[1];
            Map<String, Object> jsonData;
            try {
                jsonData = JsonUtils.readValue(new String(Base64.decodeBase64(data), StandardCharsets.UTF_8), new TypeReference<>() {
                });
                //check signature algorithm
                final var algorithm = Optional.ofNullable(jsonData)
                        .map(it -> it.get("algorithm"))
                        .orElse(null);
                if (algorithm != null && !"HMAC-SHA256".equals(algorithm)) {
                    log.debug("Unknown algorithm was used to sign request! No claims returned.");
                    return null;
                }
                //check if data is signed correctly
                if (!hmacSignAndEncode(signedRequests[1], secret).equals(signature)) {
                    log.debug("Signature is not correct, possibly the data was tampered with! No claims returned.");
                    return null;
                }
                return jsonData;
            } catch (Exception e) {
                log.error("Exception", e);
                return null;
            }
        } else if ("code".equals(config.getResponseType())
                && RawExternalOAuthIdentityProviderDefinition.class.isAssignableFrom(config.getClass())
                && config.getUserInfoUrl() != null) {
            RawExternalOAuthIdentityProviderDefinition narrowedConfig = (RawExternalOAuthIdentityProviderDefinition) config;

            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "Bearer " + idToken);
            headers.add("Accept", "application/json");

            URI requestUri;
            HttpEntity<Object> requestEntity = new HttpEntity<>(headers);
            try {
                requestUri = narrowedConfig.getUserInfoUrl().toURI();
            } catch (URISyntaxException exc) {
                log.error("Invalid user info URI configured: <{}>", narrowedConfig.getUserInfoUrl(), exc);
                return null;
            }

            log.debug("Performing token check with url:{}", requestUri);
            ResponseEntity<Map<String, Object>> responseEntity =
                    getRestTemplate(config)
                            .exchange(requestUri, GET, requestEntity,
                                    new ParameterizedTypeReference<>() {
                                    }
                            );
            log.debug("Request completed with status:{}", responseEntity.getStatusCode());
            return responseEntity.getBody();
        } else {
            JwtTokenSignedByThisUAA jwtToken = validateToken(idToken, config);
            log.debug("Decoding id_token");
            Jwt decodeIdToken = jwtToken.getJwt();
            log.debug("Deserializing id_token claims");

            return JsonUtils.readValue(decodeIdToken.getClaims(), new TypeReference<>() {
            });
        }
    }

    protected String hmacSignAndEncode(String data, String key) {
        try {
            UaaMacSigner macSigner = new UaaMacSigner(key);
            return macSigner.sign(new JWSHeader(JWSAlgorithm.HS256), data.getBytes(StandardCharsets.UTF_8)).toString();
        } catch (JOSEException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private JwtTokenSignedByThisUAA validateToken(String idToken, AbstractExternalOAuthIdentityProviderDefinition config) {
        log.debug("Validating id_token");

        JwtTokenSignedByThisUAA jwtToken;

        if (tokenEndpointBuilder.getTokenEndpoint(identityZoneManager.getCurrentIdentityZone()).equals(config.getIssuer())) {
            List<SignatureVerifier> signatureVerifiers = getTokenKeyForUaaOrigin();
            jwtToken = buildIdTokenValidator(idToken, new ChainedSignatureVerifier(signatureVerifiers), keyInfoService);
        } else {
            JsonWebKeySet<JsonWebKey> tokenKeyFromOAuth = getTokenKeyFromOAuth(config);
            jwtToken = buildIdTokenValidator(idToken, new ChainedSignatureVerifier(tokenKeyFromOAuth), keyInfoService)
                    .checkIssuer((!hasLength(config.getIssuer()) ? config.getTokenUrl().toString() : config.getIssuer()))
                    .checkAudience(config.getRelyingPartyId());
        }
        return jwtToken.checkExpiry();
    }

    protected List<SignatureVerifier> getTokenKeyForUaaOrigin() {
        Map<String, KeyInfo> keys = keyInfoService.getKeys();
        return keys.values().stream()
                .map(KeyInfo::getVerifier)
                .toList();
    }

    public JsonWebKeySet<JsonWebKey> getTokenKeyFromOAuth(AbstractExternalOAuthIdentityProviderDefinition config) {

        String tokenKey = config.getTokenKey();
        if (StringUtils.hasText(tokenKey)) {
            return JsonWebKeyHelper.parseConfiguration(tokenKey);
        }
        try {
            return oidcMetadataFetcher.fetchWebKeySet(config);
        } catch (OidcMetadataFetchingException e) {
            throw new InvalidTokenException(e.getMessage(), e);
        }
    }

    protected <T extends AbstractExternalOAuthIdentityProviderDefinition<T>> String getTokenFromCode(
            ExternalOAuthCodeToken codeToken,
            final IdentityProvider<T> provider
    ) {
        final T config = provider.getConfig();

        if (StringUtils.hasText(codeToken.getIdToken()) && ID_TOKEN.equals(getResponseType(config))) {
            log.debug("ExternalOAuthCodeToken contains id_token, not exchanging code.");
            return codeToken.getIdToken();
        }
        if (StringUtils.hasText(codeToken.getSignedRequest()) && "signed_request".equals(getResponseType(config))) {
            log.debug("ExternalOAuthCodeToken contains signed_request, not exchanging code.");
            return codeToken.getSignedRequest();
        }
        MultiValueMap<String, String> body = new LinkedMaskingMultiValueMap<>("code", "client_secret");
        body.add("grant_type", GRANT_TYPE_AUTHORIZATION_CODE);
        body.add("response_type", getResponseType(config)); // not required by the Oauth 2.0 standard in this 'Access Token Request'
        body.add("code", codeToken.getCode());
        body.add("redirect_uri", codeToken.getRedirectUrl());
        // NOTE: the "state" body parameter is optional. We also are in
        // trouble here about how to obtain the correct 'httpSession' to use.
        // body.add("state", SessionUtils.getStateParam(RequestContextHolder...httpSession, SessionUtils.stateParameterAttributeKeyForIdp(codeToken.getOrigin())))

        log.debug("Adding new client_id and client_secret for token exchange");
        body.add("client_id", config.getRelyingPartyId());

        if (config instanceof OIDCIdentityProviderDefinition oidcIdentityProviderDefinition && oidcIdentityProviderDefinition.getAdditionalAuthzParameters() != null) {
            for (Map.Entry<String, String> entry : oidcIdentityProviderDefinition.getAdditionalAuthzParameters().entrySet()) {
                body.add(entry.getKey(), entry.getValue());
            }
        }

        HttpHeaders headers = new HttpHeaders();

        // no client-secret, switch to PKCE
        // https://docs.spring.io/spring-security/site/docs/5.3.1.RELEASE/reference/html5/#initiating-the-authorization-request
        if (config.getRelyingPartySecret() == null) {
            // no secret but jwtClientAuthentication
            if (config instanceof OIDCIdentityProviderDefinition oidcDefinition && ClientAuthentication.PRIVATE_KEY_JWT.equals(
                    ClientAuthentication.getCalculatedMethod(config.getAuthMethod(), false, oidcDefinition.getJwtClientAuthentication() != null))) {

                /* ensure that the dynamic lookup of the cert and/or key for private key JWT works for an alias IdP in a
                 * custom IdZ */
                final boolean allowDynamicValueLookupInCustomZone = hasText(provider.getAliasZid()) && hasText(provider.getAliasId());
                body = new JwtClientAuthentication(keyInfoService).getClientAuthenticationParameters(
                        body,
                        oidcDefinition,
                        allowDynamicValueLookupInCustomZone
                );
            }
        } else {
            if (config.isClientAuthInBody()) {
                body.add("client_secret", config.getRelyingPartySecret());
            } else {
                String clientAuthHeader = getClientAuthHeader(config);
                headers.add("Authorization", clientAuthHeader);
            }
        }
        if (ExternalOAuthProviderConfigurator.isPkceNeeded(config)) {
            // if session is expired or other issues in retrieving code_verifier, then flow fails with 401, which is expected
            body.add("code_verifier", getSessionValue(SessionUtils.codeVerifierParameterAttributeKeyForIdp(codeToken.getOrigin())));
        }
        headers.add("Accept", "application/json");

        URI requestUri;
        HttpEntity requestEntity = new HttpEntity<>(body, headers);
        try {
            requestUri = config.getTokenUrl().toURI();
        } catch (URISyntaxException e) {
            log.error("Invalid URI configured:{}", config.getTokenUrl(), e);
            return null;
        }

        log.debug("Performing token exchange with url:{} and request:{}", requestUri, body);
        // A configuration that skips SSL/TLS validation requires clobbering the rest template request factory
        // setup by the bean initializer.
        ResponseEntity<Map<String, String>> responseEntity =
                getRestTemplate(config)
                        .exchange(requestUri,
                                HttpMethod.POST,
                                requestEntity,
                                new ParameterizedTypeReference<>() {
                                }
                        );
        log.debug("Request completed with status:{}", responseEntity.getStatusCode());
        return Optional.ofNullable(responseEntity.getBody()).map(resBody -> resBody.get(getTokenFieldName(config))).orElse(UaaStringUtils.EMPTY_STRING);
    }

    private String getSessionValue(String value) {
        try {
            ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            return (String) SessionUtils.getStateParam(attr.getRequest().getSession(false), value);
        } catch (Exception e) {
            log.warn("Exception", e);
            return "";
        }
    }

    private String getClientAuthHeader(AbstractExternalOAuthIdentityProviderDefinition config) {
        String clientAuth = new String(Base64.encodeBase64((config.getRelyingPartyId() + ":" + config.getRelyingPartySecret()).getBytes()));
        return "Basic " + clientAuth;
    }

    private String getTokenFieldName(AbstractExternalOAuthIdentityProviderDefinition config) {
        String responseType = getResponseType(config);
        if ("code".equals(responseType) || "token".equals(responseType)) {
            return "access_token"; // Oauth 2.0
        }
        return responseType;
    }

    protected void fetchMetadataAndUpdateDefinition(OIDCIdentityProviderDefinition definition) {
        try {
            oidcMetadataFetcher.fetchMetadataAndUpdateDefinition(definition);
        } catch (OidcMetadataFetchingException e) {
            log.warn("OidcMetadataFetchingException", e);
        }
    }

    public IdentityProvider<OIDCIdentityProviderDefinition> getOidcProxyIdpForTokenExchange(HttpServletRequest request) {
        return retrieveTokenExchangeIdp(UaaLoginHint.parseRequestParameter(request.getParameter("login_hint")), getAllowedProviders());
    }

    public List<String> getAllowedProviders() {
        Authentication clientAuth = SecurityContextHolder.getContext().getAuthentication();
        if (clientAuth == null) {
            throw new BadCredentialsException("No client authentication found.");
        }
        return clientAuth.getPrincipal() instanceof UaaClient uaaClient && uaaClient.getAdditionalInformation() != null ?
            (List<String>) uaaClient.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS) : null;
    }

    private IdentityProvider<OIDCIdentityProviderDefinition> retrieveTokenExchangeIdp(UaaLoginHint loginHint, List<String> allowedProviders) {
        String useOrigin = loginHint != null && loginHint.getOrigin() != null ? loginHint.getOrigin() : null;
        if (useOrigin != null) {
            try {
                IdentityProvider<?> retrievedByOrigin = getProviderProvisioning().retrieveByOrigin(useOrigin, identityZoneManager.getCurrentIdentityZoneId());
                if (retrievedByOrigin != null && retrievedByOrigin.isActive() && retrievedByOrigin.getOriginKey().equals(useOrigin)
                        && providerSupportsTokenExchange(retrievedByOrigin)
                        && (allowedProviders == null || allowedProviders.contains(useOrigin))) {
                    return (IdentityProvider<OIDCIdentityProviderDefinition>) retrievedByOrigin;
                }
            } catch (EmptyResultDataAccessException e) {
                // ignore
            }
        }
        return null;
    }

    private boolean providerSupportsTokenExchange(IdentityProvider provider) {
        if (OriginKeys.OIDC10.equals(provider.getType()) && provider.getConfig() instanceof OIDCIdentityProviderDefinition oidcProviderDefinition) {
            return Optional.ofNullable(oidcProviderDefinition.isTokenExchangeEnabled()).orElse(false);
        }
        return false;
    }

    public String oidcJwtBearerGrant(UaaAuthenticationDetails details,
                                     IdentityProvider<OIDCIdentityProviderDefinition> identityProvider,
                                     String assertion) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("assertion", assertion);
        try {
            return oauthTokenRequest(details, identityProvider, GRANT_TYPE_JWT_BEARER, params);
        } catch (HttpClientErrorException e) {
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(identityProvider.getOriginKey(), assertion);
            authenticationToken.setDetails(details);
            publish(new IdentityProviderAuthenticationFailureEvent(authenticationToken, "jwt-bearer-proxy: " + identityProvider.getOriginKey(), OriginKeys.OIDC10, identityZoneManager.getCurrentIdentityZoneId()));
            throw new BadCredentialsException(e.getResponseBodyAsString(), e);
        }
    }

    public String oauthTokenRequest(UaaAuthenticationDetails details, final IdentityProvider<OIDCIdentityProviderDefinition> identityProvider,
                                String grantType, MultiValueMap<String, String> additionalParameters) {
        final OIDCIdentityProviderDefinition config = identityProvider.getConfig();

        //Token per RestCall
        URL tokenUrl = config.getTokenUrl();
        String clientId = config.getRelyingPartyId();
        String clientSecret = config.getRelyingPartySecret();
        if (clientId == null) {
            throw new ProviderConfigurationException("External OpenID Connect provider configuration is missing relyingPartyId.");
        }
        if (clientSecret == null && config.getJwtClientAuthentication() == null && config.getAuthMethod() == null) {
            throw new ProviderConfigurationException("External OpenID Connect provider configuration is missing relyingPartySecret, jwtClientAuthentication or authMethod.");
        }
        if (tokenUrl == null) {
            fetchMetadataAndUpdateDefinition(config);
            tokenUrl = Optional.ofNullable(config.getTokenUrl()).orElseThrow(() -> new ProviderConfigurationException("External OpenID Connect metadata is missing after discovery update."));
        }
        String calcAuthMethod = ClientAuthentication.getCalculatedMethod(config.getAuthMethod(), clientSecret != null, config.getJwtClientAuthentication() != null);
        RestTemplate rt = config.isSkipSslValidation() ? trustingRestTemplate : nonTrustingRestTemplate;

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(singletonList(APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>(additionalParameters);

        if (ClientAuthentication.PRIVATE_KEY_JWT.equals(calcAuthMethod)) {
            /* ensure that the dynamic lookup of the cert and/or key for private key JWT works for an alias IdP in a
             * custom IdZ */
            final boolean allowDynamicValueLookupInCustomZone = hasText(identityProvider.getAliasZid()) && hasText(identityProvider.getAliasId());
            params = new JwtClientAuthentication(getKeyInfoService())
                    .getClientAuthenticationParameters(params, config, allowDynamicValueLookupInCustomZone);
        } else if (ClientAuthentication.secretNeeded(calcAuthMethod)) {
            String auth = clientId + ":" + clientSecret;
            headers.add("Authorization", "Basic " + Base64.encodeBase64String(auth.getBytes(StandardCharsets.UTF_8)));
        } else {
            params.add(AbstractClientParametersAuthenticationFilter.CLIENT_ID, clientId);
        }
        if (config.isSetForwardHeader() && details != null) {
            if (details.getOrigin() != null) {
                headers.add("X-Forwarded-For", details.getOrigin());
            }
        }
        params.add("grant_type", grantType);
        params.add("response_type", ID_TOKEN);
        if (ObjectUtils.isNotEmpty(config.getScopes())) {
            params.add("scope", String.join(" ", config.getScopes()));
        }

        List<Prompt> prompts = config.getPrompts();
        List<String> promptsToInclude = new ArrayList<>();
        if (prompts != null) {
            for (Prompt prompt : prompts) {
                if ("username".equals(prompt.getName()) || "password".equals(prompt.getName()) || "passcode".equals(prompt.getName())) {
                    continue;
                }
                promptsToInclude.add(prompt.getName());
            }
        }
        if (details != null) {
            for (String prompt : promptsToInclude) {
                String[] values = details.getParameterMap().get(prompt);
                if (values == null || values.length != 1 || !hasText(values[0])) {
                    continue; //No single value given, skip this parameter
                }
                params.add(prompt, values[0]);
            }
        }


        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        String idToken = null;
        ResponseEntity<Map<String, String>> tokenResponse = rt.exchange(tokenUrl.toString(), HttpMethod.POST, request, new ParameterizedTypeReference<>() {});

        if (tokenResponse.hasBody()) {
            Map<String, String> body = tokenResponse.getBody();
            idToken = body != null ? body.get(ID_TOKEN) : null;
        }
        return idToken;
    }

    @Data
    protected static class AuthenticationData {
        private Map<String, Object> claims;
        private String username;
        private List<SimpleGrantedAuthority> authorities;
        private List<SimpleGrantedAuthority> externalAuthorities;
        private Map<String, Object> attributeMappings;
    }
}
