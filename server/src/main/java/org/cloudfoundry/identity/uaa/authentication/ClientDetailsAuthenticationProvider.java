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
package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.tls.TlsClientAuthSubjectMatcher;
import org.cloudfoundry.identity.uaa.oauth.tls.TlsClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.tls.RawPeerCertificateCaptureFilter;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import tools.jackson.core.type.TypeReference;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_EMPTY;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_NONE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_PRIVATE_KEY_JWT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_TLS_CLIENT_AUTH;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.getSafeParameterValue;

/**
 * Authenticates OAuth clients for token and related endpoints. Spring Security populates
 * {@link org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails#getRequestPath()} from the servlet;
 * SAML2 bearer and similar flows may post to {@code /oauth/token/alias/...} rather than the literal path
 * {@code /oauth/token}. Prior logic treated only the exact {@code /oauth/token} path as the token endpoint for
 * {@link #isPublicTokenRequest}, which incorrectly skipped {@code private_key_jwt} validation and PKCE/refresh
 * handling for those subpaths. Matching any path under {@code /oauth/token/} aligns client authentication with
 * the actual request URI.
 */
public class ClientDetailsAuthenticationProvider extends DaoAuthenticationProvider {

    private final JwtClientAuthentication jwtClientAuthentication;
    private final TlsClientAuthentication tlsClientAuthentication;

    public ClientDetailsAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder encoder,
            JwtClientAuthentication jwtClientAuthentication, TlsClientAuthentication tlsClientAuthentication) {
        super(userDetailsService);
        setPasswordEncoder(encoder);
        this.jwtClientAuthentication = jwtClientAuthentication;
        this.tlsClientAuthentication = tlsClientAuthentication;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {


        String[] passwordList;
        String password = userDetails.getPassword();
        if (password != null) {
            passwordList = password.split(" ");
        } else {
            passwordList = new String[]{password};
        }

        AuthenticationException error = null;
        for (String pwd : passwordList) {
            try {
                UaaClient uaaClient = new UaaClient(userDetails, pwd);
                TlsClientAuthConfiguration tlsClientAuthConfiguration = getTlsClientAuthConfiguration(uaaClient);
                boolean tlsClientAuthConfigured =
                        TlsClientAuthConfiguration.isConfigured(tlsClientAuthConfiguration);
                // /oauth/mtls/token is advertised in OIDC discovery as
                // mtls_endpoint_aliases.token_endpoint (RFC 8705 section 5), so it must serve mutual-TLS
                // client authentication and nothing else. Without this check the endpoint is an
                // unrestricted alias of /oauth/token: a client with no tls-client-auth-ca that presents
                // a client_secret authenticates here exactly as it would there, and the issued token
                // records no mTLS authentication at all.
                if (isTlsClientAuthPath(authentication.getDetails()) && !tlsClientAuthConfigured) {
                    error = new BadCredentialsException(
                            "tls_client_auth: /oauth/mtls/token requires a client configured with "
                                    + "tls-client-auth-ca");
                    break;
                }
                if (tlsClientAuthConfigured) {
                    if (!ObjectUtils.isEmpty(authentication.getCredentials())
                            || !isTlsClientAuthPath(authentication.getDetails())) {
                        error = new BadCredentialsException(
                                "tls_client_auth: configured clients must authenticate at /oauth/mtls/token without client credentials");
                    } else if (tlsClientAuthConfiguration.configuredSubjectBindings().size() != 1) {
                        // RFC 8705 2.1.2 requires exactly one registered subject value. PKIX
                        // validation proves only that SOME certificate from the configured CA was
                        // presented, not that it belongs to this client -- and where the CA is
                        // shared, as Diego's instance-identity CA is across every app instance in
                        // a foundation, that lets any certificate holder obtain this client's
                        // tokens. ClientAdminEndpointsValidator rejects this shape at
                        // configuration time; this is the enforcement for clients that reached the
                        // store by another route (persisted before that check existed, written
                        // directly, or restored from a backup).
                        error = new BadCredentialsException(
                                "tls_client_auth: client is configured with tls-client-auth-ca but does not register "
                                        + "exactly one certificate subject value. Configure one of "
                                        + String.join(", ", TlsClientAuthConfiguration.SUBJECT_BINDING_PARAMETERS));
                    } else {
                        setAuthenticationMethod(authentication, CLIENT_AUTH_TLS_CLIENT_AUTH);
                        if (!validateTlsClientAuth(uaaClient)) {
                            error = new BadCredentialsException("tls_client_auth: certificate validation failed");
                        }
                    }
                    break;
                }
                if (ObjectUtils.isEmpty(authentication.getCredentials())) {
                    if (isPublicGrantTypeUsageAllowed(authentication.getDetails()) && uaaClient.isAllowPublic()) {
                        // in case of grant_type=authorization_code and code_verifier passed (PKCE) we check if client has option allowpublic with true and continue even if no secret is in request
                        setAuthenticationMethod(authentication, CLIENT_AUTH_NONE);
                        break;
                    } else if (isPrivateKeyJwt(authentication.getDetails())) {
                        setAuthenticationMethod(authentication, CLIENT_AUTH_PRIVATE_KEY_JWT);
                        if (!validatePrivateKeyJwt(authentication.getDetails(), uaaClient)) {
                            error = new BadCredentialsException("Bad client_assertion type");
                        }
                        break;
                    } else {
                        // set internally empty as client_auth_method e.g. cf client
                        setAuthenticationMethod(authentication, CLIENT_AUTH_EMPTY);
                    }
                }
                if (uaaClient.getPassword() == null) {
                    error = new BadCredentialsException("Missing credentials");
                    break;
                }
                super.additionalAuthenticationChecks(uaaClient, authentication);
                error = null;
                break;
            } catch (AuthenticationException e) {
                error = e;
            }
        }
        if (error != null) {
            throw error;
        }
    }

    private static void setAuthenticationMethod(AbstractAuthenticationToken authentication, String method) {
        if (authentication.getDetails() instanceof  UaaAuthenticationDetails) {
            ((UaaAuthenticationDetails) authentication.getDetails()).setAuthenticationMethod(method);
        }
    }

    private static boolean isPublicGrantTypeUsageAllowed(Object uaaAuthenticationDetails) {
        UaaAuthenticationDetails authenticationDetails = getUaaAuthenticationDetails(uaaAuthenticationDetails);
        Map<String, String[]> requestParameters = getRequestParameters(authenticationDetails);
        return isPublicTokenRequest(authenticationDetails) && (isAuthorizationWithPkce(requestParameters) || isRefreshFlow(requestParameters));
    }

    /**
     * Token requests use {@code /oauth/token}; SAML2 bearer and other grants may post to subpaths such as
     * {@code /oauth/token/alias/{registrationId}}. Treat those as the same endpoint for client authentication
     * (e.g. private_key_jwt) and PKCE/refresh public-client handling.
     */
    private static boolean isPublicTokenRequest(UaaAuthenticationDetails authenticationDetails) {
        if (authenticationDetails.isAuthorizationSet()) {
            return false;
        }
        String path = authenticationDetails.getRequestPath();
        return "/oauth/token".equals(path) || (path != null && path.startsWith("/oauth/token/alias/"));
    }

    private static boolean isAuthorizationWithPkce(Map<String, String[]> requestParameters) {
        return PkceValidationService.isCodeVerifierParameterValid(getSafeParameterValue(requestParameters.get("code_verifier"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_id"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("code"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("redirect_uri"))) &&
                TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE.equals(getSafeParameterValue(requestParameters.get(ClaimConstants.GRANT_TYPE)));
    }

    private static boolean isRefreshFlow(Map<String, String[]> requestParameters) {
        return StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_id")))
                && StringUtils.hasText(getSafeParameterValue(requestParameters.get("refresh_token")))
                && TokenConstants.GRANT_TYPE_REFRESH_TOKEN.equals(getSafeParameterValue(requestParameters.get(ClaimConstants.GRANT_TYPE)));
    }

    private static UaaAuthenticationDetails getUaaAuthenticationDetails(Object object) {
        return object instanceof UaaAuthenticationDetails uad ? uad : new UaaAuthenticationDetails();
    }

    private static Map<String, String[]> getRequestParameters(UaaAuthenticationDetails authenticationDetails) {
        return Optional.ofNullable(authenticationDetails.getParameterMap()).orElse(Collections.emptyMap());
    }

    private static boolean isPrivateKeyJwt(Object uaaAuthenticationDetails) {
        UaaAuthenticationDetails authenticationDetails = getUaaAuthenticationDetails(uaaAuthenticationDetails);
        Map<String, String[]> requestParameters = getRequestParameters(authenticationDetails);
        return isPublicTokenRequest(authenticationDetails) &&
                !StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_secret"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_assertion_type"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_assertion")));
    }

    private boolean validatePrivateKeyJwt(Object uaaAuthenticationDetails, UaaClient uaaClient) {
        return jwtClientAuthentication.validateClientJwt(getRequestParameters(getUaaAuthenticationDetails(uaaAuthenticationDetails)),
                uaaClient.getClientJwtConfiguration(), uaaClient.getUsername());
    }

    static boolean isTlsClientAuthPath(Object uaaAuthenticationDetails) {
        UaaAuthenticationDetails details = getUaaAuthenticationDetails(uaaAuthenticationDetails);
        String path = details != null ? details.getRequestPath() : null;
        return RawPeerCertificateCaptureFilter.isMtlsTokenPath(path);
    }

    /**
     * @throws BadCredentialsException when the presented chain does not validate. {@link
     *         TlsClientAuthentication#validateClientCert} signals that with {@link
     *         InvalidClientDetailsException}, which is a {@code UaaException} -> {@code
     *         OAuth2Exception} -> {@code RuntimeException} and NOT a Spring {@link
     *         AuthenticationException}. Spring's {@code AbstractUserDetailsAuthenticationProvider},
     *         {@code ProviderManager} and {@code BasicAuthenticationFilter} all catch only
     *         {@code AuthenticationException}, so left unconverted it escapes the whole security
     *         chain: requests carrying an {@code Authorization: Basic} header (where
     *         {@code ClientParametersAuthenticationFilter} stands down and
     *         {@code ClientBasicAuthenticationFilter} handles the request) got HTTP 500 and an
     *         ERROR-level stack trace per attempt, while the identical certificate sent with a
     *         {@code client_id} parameter got a clean 401 -- the latter only because
     *         {@code AbstractClientParametersAuthenticationFilter} happens to wrap every exception.
     *         Converting here makes the outcome identical on both paths and removes an
     *         unauthenticated log-flooding vector. The message is preserved verbatim so the response
     *         body is unchanged on the path that already worked.
     */
    boolean validateTlsClientAuth(UaaClient uaaClient) {
        // Cheap presence-only check (no config resolution, no JSON/claim-mapping parsing) before
        // doing any work to resolve this client's TlsClientAuthConfiguration.
        if (!tlsClientAuthentication.hasCertificateFromRequest()) {
            return false;
        }
        TlsClientAuthConfiguration config = getTlsClientAuthConfiguration(uaaClient);
        X509Certificate[] chain = tlsClientAuthentication.getCertificateChainFromRequest(config);
        if (chain == null || chain.length == 0) {
            return false;
        }
        try {
            // Three separate questions, in increasing cost: was it issued by the CA we trust for
            // this client (RFC 8705 2.1, chain validation); is it THIS client's certificate
            // (RFC 8705 2.1.2, subject binding); and does it satisfy any additional UAA-specific
            // required-claims constraint layered on top.
            return tlsClientAuthentication.validateClientCert(chain, config).isPresent()
                    && TlsClientAuthSubjectMatcher.matches(chain[0], config)
                    && tlsClientAuthentication.certificateSatisfiesRequiredClaims(chain[0], config);
        } catch (InvalidClientDetailsException e) {
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }

    /** A non-blank String value from the flat additionalInformation map, or {@code null}. */
    private static String flatString(Map<String, Object> info, String key) {
        return info.get(key) instanceof String value && !value.isBlank() ? value : null;
    }

    static TlsClientAuthConfiguration getTlsClientAuthConfiguration(UaaClient uaaClient) {
        Map<String, Object> info = uaaClient.getAdditionalInformation();
        if (info == null) {
            return null;
        }
        Object rawConfig = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
        if (rawConfig instanceof String pem) {
            try {
                List<TlsClientAuthConfiguration.ClaimMapping> claimMappings = null;
                Object rawMappings = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS);
                if (rawMappings instanceof String mappingsJson) {
                    claimMappings = JsonUtils.readValue(mappingsJson,
                            new TypeReference<List<TlsClientAuthConfiguration.ClaimMapping>>() {});
                } else if (rawMappings instanceof List<?> mappingsList) {
                    // Jackson may parse a JSON array directly as a List when additionalInformation
                    // is deserialized from JDBC without a String-encoded wrapper.
                    String mappingsJson = JsonUtils.writeValueAsString(mappingsList);
                    claimMappings = JsonUtils.readValue(mappingsJson,
                            new TypeReference<List<TlsClientAuthConfiguration.ClaimMapping>>() {});
                }
                String subTemplate = null;
                Object rawSubTemplate = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE);
                if (rawSubTemplate instanceof String st && !st.isBlank()) {
                    subTemplate = st;
                }

                List<String> audTemplates = null;
                Object rawAudTemplates = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES);
                if (rawAudTemplates instanceof String audJson) {
                    audTemplates = JsonUtils.readValue(audJson, new TypeReference<List<String>>() {});
                } else if (rawAudTemplates instanceof List<?> audList) {
                    audTemplates = JsonUtils.readValue(
                            JsonUtils.writeValueAsString(audList),
                            new TypeReference<List<String>>() {});
                }

                String trustedProxyCaPem = null;
                Object rawTrustedProxyCa = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA);
                if (rawTrustedProxyCa instanceof String tpc && !tpc.isBlank()) {
                    trustedProxyCaPem = tpc;
                }

                Map<String, String> requiredClaims = null;
                Object rawRequiredClaims = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS);
                if (rawRequiredClaims instanceof String requiredClaimsJson) {
                    requiredClaims = JsonUtils.readValue(requiredClaimsJson,
                            new TypeReference<Map<String, String>>() {});
                } else if (rawRequiredClaims instanceof Map<?, ?> requiredClaimsMap) {
                    requiredClaims = JsonUtils.readValue(
                            JsonUtils.writeValueAsString(requiredClaimsMap),
                            new TypeReference<Map<String, String>>() {});
                }

                TlsClientAuthConfiguration cfg = new TlsClientAuthConfiguration(pem, claimMappings);
                cfg.setSubTemplate(subTemplate);
                cfg.setAudTemplates(audTemplates);
                cfg.setTrustedProxyCaPem(trustedProxyCaPem);
                cfg.setRequiredClaims(requiredClaims);
                // RFC 8705 2.1.2 subject binding. Read from the flat additionalInformation path so
                // that clients registered through the BOSH oauth.clients bootstrap, which never
                // goes through the admin API's typed model, are bound too.
                cfg.setSubjectDn(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN));
                cfg.setSanDns(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS));
                cfg.setSanUri(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_URI));
                cfg.setSanIp(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP));
                cfg.setSanEmail(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_EMAIL));
                return cfg;
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }
}
