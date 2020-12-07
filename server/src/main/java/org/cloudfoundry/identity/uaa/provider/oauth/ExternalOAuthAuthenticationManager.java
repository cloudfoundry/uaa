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

package org.cloudfoundry.identity.uaa.provider.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.oauth.jwt.ChainedSignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.LinkedMaskingMultiValueMap;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.TokenValidation;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.MAC;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.RSA;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_VERIFIED_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.TokenValidation.buildIdTokenValidator;
import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.isAcceptedInvitationAuthentication;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.util.StringUtils.isEmpty;

public class ExternalOAuthAuthenticationManager extends ExternalLoginAuthenticationManager<ExternalOAuthAuthenticationManager.AuthenticationData> {

    public static Logger logger = LoggerFactory.getLogger(ExternalOAuthAuthenticationManager.class);

    private final RestTemplate trustingRestTemplate;
    private final RestTemplate nonTrustingRestTemplate;
    private final OidcMetadataFetcher oidcMetadataFetcher;

    private TokenEndpointBuilder tokenEndpointBuilder;
    private KeyInfoService keyInfoService;

    //origin is per thread during execution
    private final ThreadLocal<String> origin = ThreadLocal.withInitial(() -> "unknown");

    public ExternalOAuthAuthenticationManager(IdentityProviderProvisioning providerProvisioning,
                                              RestTemplate trustingRestTemplate,
                                              RestTemplate nonTrustingRestTemplate,
                                              TokenEndpointBuilder tokenEndpointBuilder,
                                              KeyInfoService keyInfoService,
                                              OidcMetadataFetcher oidcMetadataFetcher) {
        super(providerProvisioning);
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
            if (isEmpty(issuer)) {
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
                if (!isEmpty(originKey)) {
                    return buildInternalUaaIdpConfig(issuer, originKey);
                }
            }
            //All other cases: throw Exception
            throw new InsufficientAuthenticationException(String.format("Unable to map issuer, %s , to a single registered provider", issuer));
        } catch (IllegalArgumentException | JsonUtils.JsonUtilException x) {
            throw new InsufficientAuthenticationException("Unable to decode expected id_token");
        }
    }

    private IdentityProvider retrieveRegisteredIdentityProviderByIssuer(String issuer) {
        return ((ExternalOAuthProviderConfigurator) getProviderProvisioning()).retrieveByIssuer(issuer, IdentityZoneHolder.get().getId());
    }

    private Map<String, Object> parseClaimsFromIdTokenString(String idToken) {
        String claimsString = JwtHelper.decode(ofNullable(idToken).orElse("")).getClaims();
        return JsonUtils.readValue(claimsString, new TypeReference<Map<String, Object>>() {});
    }

    private boolean idTokenWasIssuedByTheUaa(String issuer) {
        return issuer.equals(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
    }

    private IdentityProvider buildInternalUaaIdpConfig(String issuer, String originKey) {
        OIDCIdentityProviderDefinition uaaOidcProviderConfig = new OIDCIdentityProviderDefinition();
        uaaOidcProviderConfig.setIssuer(issuer);
        Map<String, Object> userNameMapping = Collections.singletonMap(USER_NAME_ATTRIBUTE_NAME, USER_NAME_ATTRIBUTE_NAME);
        uaaOidcProviderConfig.setAttributeMappings(userNameMapping);
        IdentityProvider<OIDCIdentityProviderDefinition> uaaIdp = new IdentityProvider<>();
        uaaIdp.setOriginKey(originKey);
        uaaIdp.setConfig(uaaOidcProviderConfig);
        return uaaIdp;
    }

    @Override
    public AuthenticationData getExternalAuthenticationDetails(Authentication authentication) {
        IdentityProvider provider = null;
        ExternalOAuthCodeToken codeToken = (ExternalOAuthCodeToken) authentication;

        if (isEmpty(codeToken.getOrigin())) {
            provider = resolveOriginProvider(codeToken.getIdToken());
            codeToken.setOrigin(provider.getOriginKey());
        }

        setOrigin(codeToken.getOrigin());
        if (provider == null) {
            try {
                provider = getProviderProvisioning().retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
            } catch (EmptyResultDataAccessException e) {
                logger.info("No provider found for given origin");
                throw new InsufficientAuthenticationException("Could not resolve identity provider with given origin.");
            }
        }

        if (provider != null && provider.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition) {
            AuthenticationData authenticationData = new AuthenticationData();

            AbstractExternalOAuthIdentityProviderDefinition config = (AbstractExternalOAuthIdentityProviderDefinition) provider.getConfig();
            Map<String, Object> claims = getClaimsFromToken(codeToken, config);

            if (claims == null) {
                return null;
            }
            authenticationData.setClaims(claims);

            Map<String, Object> attributeMappings = config.getAttributeMappings();

            String userNameAttributePrefix = (String) attributeMappings.get(USER_NAME_ATTRIBUTE_NAME);
            String username;
            if (StringUtils.hasText(userNameAttributePrefix)) {
                username = (String) claims.get(userNameAttributePrefix);
                logger.debug(String.format("Extracted username for claim: %s and username is: %s", userNameAttributePrefix, username));
            } else {
                username = (String) claims.get(SUB);
                logger.debug(String.format("Extracted username for claim: %s and username is: %s", SUB, username));
            }
            if (!hasText(username)) {
                throw new InsufficientAuthenticationException("Unable to map claim to a username");
            }

            authenticationData.setUsername(username);

            List<? extends GrantedAuthority> authorities = extractExternalOAuthUserAuthorities(attributeMappings, claims);
            authorities = mapAuthorities(codeToken.getOrigin(), authorities);
            authenticationData.setAuthorities(authorities);
            ofNullable(attributeMappings).ifPresent(map -> authenticationData.setAttributeMappings(new HashMap<>(map)));
            return authenticationData;
        }
        logger.debug("No identity provider found for origin:"+getOrigin()+" and zone:"+IdentityZoneHolder.get().getId());
        return null;
    }

    @Override
    protected void populateAuthenticationAttributes(UaaAuthentication authentication, Authentication request, AuthenticationData authenticationData) {
        Map<String, Object> claims = authenticationData.getClaims();
        if (claims != null) {
            if (claims.get("amr") != null) {
                if (authentication.getAuthenticationMethods()==null) {
                    authentication.setAuthenticationMethods(new HashSet<>((Collection<String>) claims.get("amr")));
                } else {
                    authentication.getAuthenticationMethods().addAll((Collection<String>) claims.get("amr"));
                }
            }

            Object acr = claims.get(ClaimConstants.ACR);
            if (acr != null) {
                if (acr instanceof Map) {
                    Map<String, Object> acrMap = (Map) acr;
                    Object values = acrMap.get("values");
                    if (values instanceof Collection) {
                        authentication.setAuthContextClassRef(new HashSet<>((Collection) values));
                    } else if (values instanceof String[]) {
                        authentication.setAuthContextClassRef(new HashSet<>(Arrays.asList((String[]) values)));
                    } else {
                        logger.debug(String.format("Unrecognized ACR claim[%s] for user_id: %s", values, authentication.getPrincipal().getId()));
                    }
                } else if (acr instanceof String) {
                    authentication.setAuthContextClassRef(new HashSet(Collections.singletonList((String) acr)));
                } else {
                    logger.debug(String.format("Unrecognized ACR claim[%s] for user_id: %s", acr, authentication.getPrincipal().getId()));
                }
            }
            MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
            logger.debug("Mapping ExternalOAuth custom attributes");
            for (Map.Entry<String, Object> entry : authenticationData.getAttributeMappings().entrySet()) {
                if (entry.getKey().startsWith(USER_ATTRIBUTE_PREFIX) && entry.getValue() != null) {
                    String key = entry.getKey().substring(USER_ATTRIBUTE_PREFIX.length());
                    Object values = claims.get(entry.getValue());
                    if (values != null) {
                        logger.debug(String.format("Mapped ExternalOAuth attribute %s to %s", key, values));
                        if (values instanceof List) {
                            List list = (List)values;
                            List<String> strings = (List<String>) list.stream()
                                .map(object -> Objects.toString(object, null))
                                .collect(Collectors.toList());
                            userAttributes.put(key, strings);
                        } else if (values instanceof String) {
                            userAttributes.put(key, Collections.singletonList((String) values));
                        } else {
                            userAttributes.put(key, Collections.singletonList(values.toString()));
                        }
                    }
                }
            }
            authentication.setUserAttributes(userAttributes);
            authentication.setExternalGroups(
                ofNullable(
                    authenticationData.getAuthorities()
                )
                .orElse(emptyList())
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet())
            );
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
            String givenName = (String) claims.get(givenNameClaim == null ? "given_name" : givenNameClaim);
            String familyName = (String) claims.get(familyNameClaim == null ? "family_name" : familyNameClaim);
            String phoneNumber = (String) claims.get(phoneClaim == null ? "phone_number" : phoneClaim);
            String email = (String) claims.get(emailClaim == null ? "email" : emailClaim);
            Object verifiedObj = claims.get(emailVerifiedClaim == null ? "email_verified" : emailVerifiedClaim);
            boolean verified =  verifiedObj instanceof Boolean ? (Boolean)verifiedObj: false;

            if (email == null) {
                email = generateEmailIfNull(username);
            }

            logger.debug(String.format("Returning user data for username:%s, email:%s", username, email));

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
                    .withZoneId(IdentityZoneHolder.get().getId())
                    .withSalt(null)
                    .withPasswordLastModified(null));
        }
        logger.debug("Authenticate data is missing, unable to return user");
        return null;
    }

    private List<? extends GrantedAuthority> extractExternalOAuthUserAuthorities(Map<String, Object> attributeMappings, Map<String, Object> claims) {
        List<String> groupNames = new LinkedList<>();
        if (attributeMappings.get(GROUP_ATTRIBUTE_NAME) instanceof String) {
            groupNames.add((String) attributeMappings.get(GROUP_ATTRIBUTE_NAME));
        } else if (attributeMappings.get(GROUP_ATTRIBUTE_NAME) instanceof Collection) {
            groupNames.addAll((Collection) attributeMappings.get(GROUP_ATTRIBUTE_NAME));
        }
        logger.debug("Extracting ExternalOAuth group names:"+groupNames);

        Set<String> scopes = new HashSet<>();
        for (String g : groupNames) {
            Object roles = claims.get(g);
            if (roles instanceof String) {
                scopes.addAll(Arrays.asList(((String) roles).split(",")));
            } else if (roles instanceof Collection) {
                scopes.addAll((Collection<? extends String>) roles);
            }
        }

        List<ExternalOAuthUserAuthority> authorities = new ArrayList<>();
        for (String scope : scopes) {
            authorities.add(new ExternalOAuthUserAuthority(scope));
        }

        return authorities;
    }

    @Override
    protected UaaUser userAuthenticated(Authentication request, UaaUser userFromRequest, UaaUser userFromDb) {
        boolean userModified = false;
        boolean is_invitation_acceptance = isAcceptedInvitationAuthentication();
        String email = userFromRequest.getEmail();
        logger.debug("ExternalOAuth user authenticated:"+email);
        if (is_invitation_acceptance) {
            String invitedUserId = (String) RequestContextHolder.currentRequestAttributes().getAttribute("user_id", RequestAttributes.SCOPE_SESSION);
            logger.debug("ExternalOAuth user accepted invitation, user_id:"+invitedUserId);
            userFromDb = getUserDatabase().retrieveUserById(invitedUserId);
            if (email != null) {
                if (!email.equalsIgnoreCase(userFromDb.getEmail())) {
                    throw new BadCredentialsException("OAuth User email mismatch. Authenticated email doesn't match invited email.");
                }
            }
            publish(new InvitedUserAuthenticatedEvent(userFromDb));
            userFromDb = getUserDatabase().retrieveUserById(invitedUserId);
        }

        //we must check and see if the email address has changed between authentications
        if (haveUserAttributesChanged(userFromDb, userFromRequest) && isRegisteredIdpAuthentication(request)) {
            logger.debug("User attributed have changed, updating them.");
            userFromDb = userFromDb.modifyAttributes(email,
                                                     userFromRequest.getGivenName(),
                                                     userFromRequest.getFamilyName(),
                                                     userFromRequest.getPhoneNumber(),
                                                     userFromRequest.getExternalId(),
                                                     userFromDb.isVerified() || userFromRequest.isVerified())
                .modifyUsername(userFromRequest.getUsername());
            userModified = true;
        }

        ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(userFromDb, userModified, userFromRequest.getAuthorities(), true);
        publish(event);
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
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> provider = getProviderProvisioning().retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
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
            if ("signed_request".equals(config.getResponseType()))
                return "signed_request";
            else if ("code".equals(config.getResponseType()))
                return "code";
            else
                return "token";
        } else if (OIDCIdentityProviderDefinition.class.isAssignableFrom(config.getClass())) {
            return "id_token";
        } else {
            throw new IllegalArgumentException("Unknown type for provider.");
        }
    }

    protected Map<String, Object> getClaimsFromToken(ExternalOAuthCodeToken codeToken,
                                                     AbstractExternalOAuthIdentityProviderDefinition config) {
        String idToken = getTokenFromCode(codeToken, config);
        return getClaimsFromToken(idToken, config);
    }

    protected Map<String, Object> getClaimsFromToken(String idToken,
                                                     AbstractExternalOAuthIdentityProviderDefinition config) {
        logger.debug("Extracting claims from id_token");
        if (idToken == null) {
            logger.debug("id_token is null, no claims returned.");
            return null;
        }

        if ("signed_request".equals(config.getResponseType())) {
            String secret = config.getRelyingPartySecret();
            logger.debug("Validating signed_request: " + idToken);
            //split request into signature and data
            String[] signedRequests = idToken.split("\\.", 2);
            //parse signature
            String signature = signedRequests[0];
            //parse data and convert to json object
            String data = signedRequests[1];
            Map<String, Object> jsonData = null;
            try {
                jsonData = JsonUtils.readValue(new String(Base64.decodeBase64(data), StandardCharsets.UTF_8), new TypeReference<Map<String,Object>>() {});
                //check signature algorithm
                if(!jsonData.get("algorithm").equals("HMAC-SHA256")) {
                    logger.debug("Unknown algorithm was used to sign request! No claims returned.");
                    return null;
                }
                //check if data is signed correctly
                if(!hmacSignAndEncode(signedRequests[1], secret).equals(signature)) {
                    logger.debug("Signature is not correct, possibly the data was tampered with! No claims returned.");
                    return null;
                }
                //logger.debug("Deserializing id_token claims: " + decodeIdToken.getClaims());
                return jsonData;
            } catch (Exception e) {
                logger.error("Exception", e);
                return null;
            }
        } else if ("code".equals(config.getResponseType())
                && RawExternalOAuthIdentityProviderDefinition.class.isAssignableFrom(config.getClass())
                && ((RawExternalOAuthIdentityProviderDefinition) config).getUserInfoUrl() != null) {
            RawExternalOAuthIdentityProviderDefinition narrowedConfig = (RawExternalOAuthIdentityProviderDefinition) config;

            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "token " + idToken);
            headers.add("Accept", "application/json");

            URI requestUri;
            HttpEntity<Object> requestEntity = new HttpEntity<>(headers);
            try {
                requestUri = narrowedConfig.getUserInfoUrl().toURI();
            } catch (URISyntaxException exc) {
                logger.error("Invalid user info URI configured: <" + narrowedConfig.getUserInfoUrl() + ">", exc);
                return null;
            }

            logger.debug(String.format("Performing token check with url:%s", requestUri));
            ResponseEntity<Map<String, Object>> responseEntity =
                getRestTemplate(config)
                    .exchange(requestUri, GET, requestEntity,
                              new ParameterizedTypeReference<Map<String, Object>>() {
                              }
                    );
            logger.debug(String.format("Request completed with status:%s", responseEntity.getStatusCode()));
            return responseEntity.getBody();
        } else {
            TokenValidation validation = validateToken(idToken, config);
            logger.debug("Decoding id_token");
            Jwt decodeIdToken = validation.getJwt();
            logger.debug("Deserializing id_token claims");

            return JsonUtils.readValue(decodeIdToken.getClaims(), new TypeReference<Map<String, Object>>() {});

        }
    }

    protected String hmacSignAndEncode(String data, String key) {
        MacSigner macSigner = new MacSigner(key);
        return new String(Base64.encodeBase64URLSafe(macSigner.sign(data.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);
    }

    private TokenValidation validateToken(String idToken, AbstractExternalOAuthIdentityProviderDefinition config) {
        logger.debug("Validating id_token");

        TokenValidation validation;

        if (tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()).equals(config.getIssuer())) {
            List<SignatureVerifier> signatureVerifiers = getTokenKeyForUaaOrigin();
            validation = buildIdTokenValidator(idToken, new ChainedSignatureVerifier(signatureVerifiers), keyInfoService);
        } else {
            JsonWebKeySet<JsonWebKey> tokenKeyFromOAuth = getTokenKeyFromOAuth(config);
            validation = buildIdTokenValidator(idToken, new ChainedSignatureVerifier(tokenKeyFromOAuth), keyInfoService)
                .checkIssuer((isEmpty(config.getIssuer()) ? config.getTokenUrl().toString() : config.getIssuer()))
                .checkAudience(config.getRelyingPartyId());
        }
        return validation.checkExpiry();
    }

    protected List<SignatureVerifier> getTokenKeyForUaaOrigin() {
        Map<String, KeyInfo> keys = keyInfoService.getKeys();
        return keys.values().stream()
          .map(i -> i.getVerifier())
          .collect(Collectors.toList());

    }

    private static boolean isAssymetricKey(String key) {
        return key.startsWith("-----BEGIN");
    }

    private JsonWebKeySet<JsonWebKey> getTokenKeyFromOAuth(AbstractExternalOAuthIdentityProviderDefinition config) {

        String tokenKey = config.getTokenKey();
        if (StringUtils.hasText(tokenKey)) {
            Map<String, Object> p = new HashMap<>();
            p.put("value", tokenKey);
            p.put("kty", isAssymetricKey(tokenKey) ? RSA.name() : MAC.name());
            logger.debug("Key configured, returning.");
            return new JsonWebKeySet<>(Collections.singletonList(new JsonWebKey(p)));
        }
        try {
            return oidcMetadataFetcher.fetchWebKeySet(config);
        } catch (OidcMetadataFetchingException e) {
            throw new InvalidTokenException(e.getMessage(), e);
        }
    }

    private String getTokenFromCode(ExternalOAuthCodeToken codeToken, AbstractExternalOAuthIdentityProviderDefinition config) {
        if (StringUtils.hasText(codeToken.getIdToken()) && "id_token".equals(getResponseType(config))) {
            logger.debug("ExternalOAuthCodeToken contains id_token, not exchanging code.");
            return codeToken.getIdToken();
        }
        if (StringUtils.hasText(codeToken.getSignedRequest()) && "signed_request".equals(getResponseType(config))) {
            logger.debug("ExternalOAuthCodeToken contains signed_request, not exchanging code.");
            return codeToken.getSignedRequest();
        }
        MultiValueMap<String, String> body = new LinkedMaskingMultiValueMap<>("code", "client_secret");
        body.add("grant_type", GRANT_TYPE_AUTHORIZATION_CODE);
        body.add("response_type", getResponseType(config)); // not required by the Oauth 2.0 standard in this 'Access Token Request'
        body.add("code", codeToken.getCode());
        body.add("redirect_uri", codeToken.getRedirectUrl());
        // NOTE: the "state" body parameter is optional. We also are in
        // trouble here about how to obtain the correct 'httpSession' to use.
//         body.add("state", SessionUtils.getStateParam(RequestContextHolder...httpSession, SessionUtils.stateParameterAttributeKeyForIdp(codeToken.getOrigin())));

        logger.debug("Adding new client_id and client_secret for token exchange");
        body.add("client_id", config.getRelyingPartyId());

        HttpHeaders headers = new HttpHeaders();

        if(config.isClientAuthInBody()) {
            body.add("client_secret", config.getRelyingPartySecret());
        } else {
            String clientAuthHeader = getClientAuthHeader(config);
            headers.add("Authorization", clientAuthHeader);
        }
        headers.add("Accept", "application/json");

        URI requestUri;
        HttpEntity requestEntity = new HttpEntity<>(body, headers);
        try {
            requestUri = config.getTokenUrl().toURI();
        } catch (URISyntaxException e) {
            logger.error("Invalid URI configured:"+config.getTokenUrl(), e);
            return null;
        }

        logger.debug(String.format("Performing token exchange with url:%s and request:%s", requestUri, body));
        // A configuration that skips SSL/TLS validation requires clobbering the rest template request factory
        // setup by the bean initializer.
        ResponseEntity<Map<String, String>> responseEntity =
            getRestTemplate(config)
                .exchange(requestUri,
                          HttpMethod.POST,
                          requestEntity,
                          new ParameterizedTypeReference<Map<String, String>>() {
                          }
                );
        logger.debug(String.format("Request completed with status:%s", responseEntity.getStatusCode()));
        return responseEntity.getBody().get(getTokenFieldName(config));
    }

    private String getClientAuthHeader(AbstractExternalOAuthIdentityProviderDefinition config) {
        String clientAuth = new String(Base64.encodeBase64((config.getRelyingPartyId() + ":" + config.getRelyingPartySecret()).getBytes()));
        return "Basic " + clientAuth;
    }

    private String getTokenFieldName(AbstractExternalOAuthIdentityProviderDefinition config) {
        String responseType = getResponseType(config);
        if (responseType == "code" || responseType == "token") {
            return "access_token"; // Oauth 2.0
        }
        return responseType;
    }

    public void setTokenEndpointBuilder(TokenEndpointBuilder tokenEndpointBuilder) {
        this.tokenEndpointBuilder = tokenEndpointBuilder;
    }

    public KeyInfoService getKeyInfoService() {
        return keyInfoService;
    }

    protected static class AuthenticationData {

        private Map<String, Object> claims;
        private String username;
        private List<? extends GrantedAuthority> authorities;
        private Map<String, Object> attributeMappings;

        public Map<String, Object> getAttributeMappings() {
            return attributeMappings;
        }

        public void setAttributeMappings(Map<String, Object> attributeMappings) {
            this.attributeMappings = attributeMappings;
        }

        public void setClaims(Map<String, Object> claims) {
            this.claims = claims;
        }

        public Map<String, Object> getClaims() {
            return claims;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getUsername() {
            return username;
        }


        public List<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }

        public void setAuthorities(List<? extends GrantedAuthority> authorities) {
            this.authorities = authorities;
        }
    }
}
