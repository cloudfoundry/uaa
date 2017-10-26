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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.TokenKeyEndpoint;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeyHelper;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.oauth.jwt.ChainedSignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.CommonSigner;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.*;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.*;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.http.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;


import java.net.MalformedURLException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.MAC;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.RSA;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.*;
import static org.cloudfoundry.identity.uaa.util.TokenValidation.validate;
import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.isAcceptedInvitationAuthentication;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.util.StringUtils.isEmpty;

public class XOAuthAuthenticationManager extends ExternalLoginAuthenticationManager<XOAuthAuthenticationManager.AuthenticationData> {

    public static Log logger = LogFactory.getLog(XOAuthAuthenticationManager.class);

    private final RestTemplateFactory restTemplateFactory;

    private UaaTokenServices tokenServices;

    //origin is per thread during execution
    private final ThreadLocal<String> origin = ThreadLocal.withInitial(() -> "unknown");

    public XOAuthAuthenticationManager(IdentityProviderProvisioning providerProvisioning, RestTemplateFactory restTemplateFactory) {
        super(providerProvisioning);
        this.restTemplateFactory = restTemplateFactory;
    }

    @Override
    public String getOrigin() {
        //origin is per thread during execution
        return origin.get();
    }

    @Override
    public void setOrigin(String origin) {
        //origin is per thread during execution
        this.origin.set(origin);
    }

    public IdentityProvider resolveOriginProvider(String idToken, String contextPath) throws AuthenticationException {
        try {
            String claimsString = JwtHelper.decode(ofNullable(idToken).orElse("")).getClaims();
            Map<String, Object> claims = JsonUtils.readValue(claimsString, new TypeReference<Map<String, Object>>() {});
            String issuer = (String) claims.get(ClaimConstants.ISS);

            if (isEmpty(issuer)) {
                throw new InsufficientAuthenticationException("Issuer is missing in id_token");
            }

            if (tokenServices.getTokenEndpoint().equals(issuer)) {
                OIDCIdentityProviderDefinition uaaOidcProviderConfig = new OIDCIdentityProviderDefinition();
                uaaOidcProviderConfig.setTokenKeyUrl(new URL(contextPath + "/token_keys"));
                uaaOidcProviderConfig.setIssuer(issuer);
                IdentityProvider uaaIdp = new IdentityProvider();
                uaaIdp.setOriginKey(OriginKeys.UAA);
                uaaIdp.setConfig(uaaOidcProviderConfig);
                return uaaIdp;
            }

            try {
                return ((XOAuthProviderConfigurator) getProviderProvisioning()).retrieveByIssuer(issuer, IdentityZoneHolder.get().getId());
            } catch (IncorrectResultSizeDataAccessException x) {
                throw new InsufficientAuthenticationException(String.format("Unable to map issuer, %s , to a single registered provider", issuer));
            }
        } catch (IllegalArgumentException | JsonUtils.JsonUtilException x) {
            throw new InsufficientAuthenticationException("Unable to decode expected id_token");
        } catch (MalformedURLException x) {
            throw new InsufficientAuthenticationException("Unable to derive context path from request URL");
        }
    }

    @Override
    public AuthenticationData getExternalAuthenticationDetails(Authentication authentication) {
        IdentityProvider provider = null;

        XOAuthCodeToken codeToken = (XOAuthCodeToken) authentication;

        if (isEmpty(codeToken.getOrigin())) {
            provider = resolveOriginProvider(codeToken.getIdToken(), codeToken.getRequestContextPath());
            codeToken.setOrigin(provider.getOriginKey());
        }

        setOrigin(codeToken.getOrigin());
        if (provider == null) {
            provider = getProviderProvisioning().retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
        }

        if (provider != null && provider.getConfig() instanceof AbstractXOAuthIdentityProviderDefinition) {
            AuthenticationData authenticationData = new AuthenticationData();

            AbstractXOAuthIdentityProviderDefinition config = (AbstractXOAuthIdentityProviderDefinition) provider.getConfig();
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
            Collection<String> groupWhiteList = config.getExternalGroupsWhitelist();

            List<? extends GrantedAuthority> authorities = extractXOAuthUserAuthorities(attributeMappings, claims, groupWhiteList);
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
                    authentication.setAuthContextClassRef(new HashSet(Arrays.asList((String) acr)));
                } else {
                    logger.debug(String.format("Unrecognized ACR claim[%s] for user_id: %s", acr, authentication.getPrincipal().getId()));
                }
            }
            MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
            logger.debug("Mapping XOauth custom attributes");
            for (Map.Entry<String, Object> entry : authenticationData.getAttributeMappings().entrySet()) {
                if (entry.getKey().startsWith(USER_ATTRIBUTE_PREFIX) && entry.getValue() != null) {
                    String key = entry.getKey().substring(USER_ATTRIBUTE_PREFIX.length());
                    Object values = claims.get(entry.getValue());
                    if (values != null) {
                        logger.debug(String.format("Mapped XOauth attribute %s to %s", key, values));
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

            Map<String, Object> claims = authenticationData.getClaims();

            String username = authenticationData.getUsername();
            String givenName = (String) claims.get(givenNameClaim == null ? "given_name" : givenNameClaim);
            String familyName = (String) claims.get(familyNameClaim == null ? "family_name" : familyNameClaim);
            String phoneNumber = (String) claims.get(phoneClaim == null ? "phone_number" : phoneClaim);
            String email = (String) claims.get(emailClaim == null ? "email" : emailClaim);

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
                    .withVerified(true)
                    .withZoneId(IdentityZoneHolder.get().getId())
                    .withSalt(null)
                    .withPasswordLastModified(null));
        }
        logger.debug("Authenticate data is missing, unable to return user");
        return null;
    }

    protected List<? extends GrantedAuthority> extractXOAuthUserAuthorities(Map<String, Object> attributeMappings, Map<String, Object> claims, Collection<String> groupWhiteList) {
        List<String> groupNames = new LinkedList<>();
        if (attributeMappings.get(GROUP_ATTRIBUTE_NAME) instanceof String) {
            groupNames.add((String) attributeMappings.get(GROUP_ATTRIBUTE_NAME));
        } else if (attributeMappings.get(GROUP_ATTRIBUTE_NAME) instanceof Collection) {
            groupNames.addAll((Collection) attributeMappings.get(GROUP_ATTRIBUTE_NAME));
        }
        logger.debug("Extracting XOauth group names:"+groupNames);

        Set<String> scopes = new HashSet<>();
        for (String g : groupNames) {
            Object roles = claims.get(g);
            if (roles instanceof String) {
                scopes.addAll(Arrays.asList(((String) roles).split(",")));
            } else if (roles instanceof Collection) {
                scopes.addAll((Collection<? extends String>) roles);
            }
        }
        logger.debug("Filtering XOauth scopes:"+scopes);
        scopes = UaaStringUtils.retainAllMatches(scopes, groupWhiteList);
        logger.debug("Filtered XOauth scopes:"+scopes);

        List<XOAuthUserAuthority> authorities = new ArrayList<>();
        for (String scope : scopes) {
            authorities.add(new XOAuthUserAuthority(scope));
        }

        return authorities;
    }

    @Override
    protected UaaUser userAuthenticated(Authentication request, UaaUser userFromRequest, UaaUser userFromDb) {
        boolean userModified = false;
        boolean is_invitation_acceptance = isAcceptedInvitationAuthentication();
        String email = userFromRequest.getEmail();
        logger.debug("XOAUTH user authenticated:"+email);
        if (is_invitation_acceptance) {
            String invitedUserId = (String) RequestContextHolder.currentRequestAttributes().getAttribute("user_id", RequestAttributes.SCOPE_SESSION);
            logger.debug("XOAUTH user accepted invitation, user_id:"+invitedUserId);
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
        if (request.getPrincipal() != null) {
            if (haveUserAttributesChanged(userFromDb, userFromRequest)) {
                logger.debug("User attributed have changed, updating them.");
                userFromDb = userFromDb.modifyAttributes(email, userFromRequest.getGivenName(), userFromRequest.getFamilyName(), userFromRequest.getPhoneNumber()).modifyUsername(userFromRequest.getUsername());
                userModified = true;
            }
        }

        ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(userFromDb, userModified, userFromRequest.getAuthorities(), true);
        publish(event);
        return getUserDatabase().retrieveUserById(userFromDb.getId());
    }

    @Override
    protected boolean isAddNewShadowUser() {
        if (!super.isAddNewShadowUser()) {
            return false;
        }
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> provider = getProviderProvisioning().retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
        return provider.getConfig().isAddShadowUserOnLogin();
    }

    public RestTemplate getRestTemplate(AbstractXOAuthIdentityProviderDefinition config) {
        return restTemplateFactory.getRestTemplate(config.isSkipSslValidation());
    }

    protected String getResponseType(AbstractXOAuthIdentityProviderDefinition config) {
        if (RawXOAuthIdentityProviderDefinition.class.isAssignableFrom(config.getClass())) {
            if ("signed_request".equals(config.getResponseType()))
                return "signed_request";
            else
                return "token";
        } else if (OIDCIdentityProviderDefinition.class.isAssignableFrom(config.getClass())) {
            return "id_token";
        } else {
            throw new IllegalArgumentException("Unknown type for provider.");
        }
    }

    protected Map<String, Object> getClaimsFromToken(XOAuthCodeToken codeToken,
                                                     AbstractXOAuthIdentityProviderDefinition config) {
        String idToken = getTokenFromCode(codeToken, config);
        return getClaimsFromToken(idToken, config);
    }

    protected Map<String, Object> getClaimsFromToken(String idToken,
                                                     AbstractXOAuthIdentityProviderDefinition config) {
        logger.debug("Extracting claims from id_token");
        if (idToken == null) {
            logger.debug("id_token is null, no claims returned.");
            return null;
        }

        if ("signed_request".equals(config.getResponseType())) {
            String signedRequest = idToken;
            String secret = config.getRelyingPartySecret();
            logger.debug("Validating signed_request: " + signedRequest);
            //split request into signature and data
            String[] signedRequests = signedRequest.split("\\.", 2);
            //parse signature
            String signature = signedRequests[0];
            //parse data and convert to json object
            String data = signedRequests[1];
            Map<String, Object> jsonData = null;
            try {
                jsonData = JsonUtils.readValue(new String(Base64.decodeBase64(data), "UTF-8"), new TypeReference<Map<String,Object>>() {});
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
            } catch (UnsupportedEncodingException e) {
                logger.error(e);
                return null;
            } catch (Exception e) {
                logger.error(e);
                return null;
            }
        } else {
            TokenValidation validation = validateToken(idToken, config);
            logger.debug("Decoding id_token");
            Jwt decodeIdToken = validation.getJwt();
            logger.debug("Deserializing id_token claims");

            return JsonUtils.readValue(decodeIdToken.getClaims(), new TypeReference<Map<String, Object>>() {});

        }
    }

    protected String hmacSignAndEncode(String data, String key) throws Exception {
        Signer signer = new CommonSigner("",key);
        return new String(Base64.encodeBase64URLSafe(signer.sign(data.getBytes("UTF-8"))), "UTF-8");
    }

    private TokenValidation validateToken(String idToken, AbstractXOAuthIdentityProviderDefinition config) {
        logger.debug("Validating id_token");

        JsonWebKeySet tokenKey;
        TokenValidation validation;
        if (tokenServices.getTokenEndpoint().equals(config.getIssuer())) {
            tokenKey = getTokenKeyForUaaOrigin();
            validation = validate(idToken)
                .checkSignature(new ChainedSignatureVerifier(tokenKey));
        } else {
            tokenKey = getTokenKeyFromOAuth(config);
            validation = validate(idToken)
                .checkSignature(new ChainedSignatureVerifier(tokenKey))
                .checkIssuer((isEmpty(config.getIssuer()) ? config.getTokenUrl().toString() : config.getIssuer()))
                .checkAudience(config.getRelyingPartyId());
        }
        return validation.checkExpiry().throwIfInvalid();
    }

    protected JsonWebKeySet<JsonWebKey> getTokenKeyForUaaOrigin() {
        Map<String, KeyInfo> keys = KeyInfo.getKeys();
        List<Map<String, Object>> resultMaps = keys.values().stream()
            .map(TokenKeyEndpoint::getResultMap)
            .collect(Collectors.toList());
        return JsonWebKeyHelper.fromResultMaps(resultMaps);
    }

    private JsonWebKeySet<JsonWebKey> getTokenKeyFromOAuth(AbstractXOAuthIdentityProviderDefinition config) {
        String tokenKey = config.getTokenKey();
        if (StringUtils.hasText(tokenKey)) {
            Map<String, Object> p = new HashMap<>();
            p.put("value", tokenKey);
            p.put("kty", KeyInfo.isAssymetricKey(tokenKey) ? RSA.name() : MAC.name());
            logger.debug("Key configured, returning.");
            return new JsonWebKeySet<>(Arrays.asList(new JsonWebKey(p)));
        }
        URL tokenKeyUrl = config.getTokenKeyUrl();
        if (tokenKeyUrl == null || !StringUtils.hasText(tokenKeyUrl.toString())) {
            return new JsonWebKeySet<>(Collections.emptyList());
        }

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Authorization", getClientAuthHeader(config));
        headers.add("Accept", "application/json");
        HttpEntity tokenKeyRequest = new HttpEntity<>(null, headers);
        logger.debug("Fetching token keys from:"+tokenKeyUrl);
        ResponseEntity<String> responseEntity = getRestTemplate(config).exchange(tokenKeyUrl.toString(), HttpMethod.GET, tokenKeyRequest, String.class);
        logger.debug("Token key response:"+responseEntity.getStatusCode());
        if (responseEntity.getStatusCode() == HttpStatus.OK) {
            return JsonWebKeyHelper.deserialize(responseEntity.getBody());
        } else {
            throw new InvalidTokenException("Unable to fetch verification keys, status:" + responseEntity.getStatusCode());
        }
    }

    private String getTokenFromCode(XOAuthCodeToken codeToken, AbstractXOAuthIdentityProviderDefinition config) {
        if (StringUtils.hasText(codeToken.getIdToken()) && "id_token".equals(getResponseType(config))) {
            logger.debug("XOauthCodeToken contains id_token, not exchanging code.");
            return codeToken.getIdToken();
        }
        if (StringUtils.hasText(codeToken.getSignedRequest()) && "signed_request".equals(getResponseType(config))) {
            logger.debug("XOauthCodeToken contains signed_request, not exchanging code.");
            return codeToken.getSignedRequest();
        }
        MultiValueMap<String, String> body = new LinkedMaskingMultiValueMap<>("code", "client_secret");
        body.add("grant_type", "authorization_code");
        body.add("response_type", getResponseType(config));
        body.add("code", codeToken.getCode());
        body.add("redirect_uri", codeToken.getRedirectUrl());

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

        try {
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
            return responseEntity.getBody().get(getResponseType(config));
        } catch (HttpServerErrorException | HttpClientErrorException ex) {
            throw ex;
        }
    }

    private String getClientAuthHeader(AbstractXOAuthIdentityProviderDefinition config) {
        String clientAuth = new String(Base64.encodeBase64((config.getRelyingPartyId() + ":" + config.getRelyingPartySecret()).getBytes()));
        return "Basic " + clientAuth;
    }

    public void setUaaTokenServices(UaaTokenServices tokenServices) {
        this.tokenServices = tokenServices;
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
