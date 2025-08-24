package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.beans.ApplicationContextProvider;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetchingException;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.springframework.context.ApplicationContext;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.isNotEmpty;

public class JwtClientAuthentication {

    public static final String GRANT_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public static final String CLIENT_ASSERTION = "client_assertion";
    public static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";
    private static final Pattern DYNAMIC_VALUE_PARAMETER_PATTERN = Pattern.compile("^\\$\\{(?<name>[\\w.\\-]++)(:++(?<default>[\\w:./=+\\-]++)*+)?}$");

    // no signature check with invalid algorithms
    private static final Set<Algorithm> NOT_SUPPORTED_ALGORITHMS = Set.of(Algorithm.NONE, JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512);
    private static final Set<String> JWT_REQUIRED_CLAIMS = Set.of(ClaimConstants.ISS, ClaimConstants.SUB, ClaimConstants.AUD,
            ClaimConstants.EXPIRY_IN_SECONDS, ClaimConstants.JTI);

    private final KeyInfoService keyInfoService;
    private final OidcMetadataFetcher oidcMetadataFetcher;
    private final ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;

    public JwtClientAuthentication(
            KeyInfoService keyInfoService) {
        this(keyInfoService, null, null);
    }

    public JwtClientAuthentication(KeyInfoService keyInfoService, OidcMetadataFetcher oidcMetadataFetcher, ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager) {
        this.keyInfoService = keyInfoService;
        this.oidcMetadataFetcher = oidcMetadataFetcher;
        this.externalOAuthAuthenticationManager = externalOAuthAuthenticationManager;
    }

    public String getClientAssertion(final OIDCIdentityProviderDefinition config) {
        return getClientAssertion(config, false);
    }

    public String getClientAssertion(
            OIDCIdentityProviderDefinition config,
            final boolean allowDynamicValueLookupInCustomZone
    ) {
        HashMap<String, String> jwtClientConfiguration = Optional.ofNullable(getJwtClientConfigurationElements(config.getJwtClientAuthentication())).orElse(new HashMap<>());
        String subject = readJwtClientOption(jwtClientConfiguration.get("sub"), config.getRelyingPartyId(), allowDynamicValueLookupInCustomZone);
        String issuer = readJwtClientOption(jwtClientConfiguration.get("iss"), config.getRelyingPartyId(), allowDynamicValueLookupInCustomZone);
        String audience = readJwtClientOption(jwtClientConfiguration.get("aud"), config.getTokenUrl().toString(), allowDynamicValueLookupInCustomZone);
        String kid = readJwtClientOption(jwtClientConfiguration.get("kid"), keyInfoService.getActiveKey().keyId(), allowDynamicValueLookupInCustomZone);
        Claims claims = new Claims();
        claims.setAud(Collections.singletonList(audience));
        claims.setSub(subject);
        claims.setIss(issuer);
        claims.setJti(UUID.randomUUID().toString().replace("-", ""));
        claims.setIat((int) Instant.now().minusSeconds(120).getEpochSecond());
        claims.setExp(Instant.now().plusSeconds(300).getEpochSecond());
        KeyInfo signingKeyInfo = loadKeyInfo(keyInfoService, jwtClientConfiguration, kid, allowDynamicValueLookupInCustomZone);
        return signingKeyInfo.verifierCertificate().isPresent() ?
                JwtHelper.encodePlusX5t(claims.getClaimMap(), signingKeyInfo, signingKeyInfo.verifierCertificate().orElseThrow()).getEncoded() :
                JwtHelper.encode(claims.getClaimMap(), signingKeyInfo).getEncoded();
    }

    public MultiValueMap<String, String> getClientAuthenticationParameters(
            final MultiValueMap<String, String> params,
            final OIDCIdentityProviderDefinition config
    ) {
        return getClientAuthenticationParameters(params, config, false);
    }

    public MultiValueMap<String, String> getClientAuthenticationParameters(
            MultiValueMap<String, String> params,
            OIDCIdentityProviderDefinition config,
            final boolean allowDynamicValueLookupInCustomZone
    ) {
        if (Objects.isNull(config) || Objects.isNull(getJwtClientConfigurationElements(config.getJwtClientAuthentication()))) {
            return params;
        }
        if (!params.containsKey("client_id")) {
            params.add("client_id", config.getRelyingPartyId());
        }
        params.add(CLIENT_ASSERTION_TYPE, GRANT_TYPE);
        params.add(CLIENT_ASSERTION, getClientAssertion(config, allowDynamicValueLookupInCustomZone));
        return params;
    }

    private static HashMap<String, String> getJwtClientConfigurationElements(Object jwtClientAuthentication) {
        HashMap<String, String> jwtClientConfiguration = null;
        if (jwtClientAuthentication instanceof Boolean boolean1 && boolean1) {
            jwtClientConfiguration = new HashMap<>();
        } else if (jwtClientAuthentication instanceof HashMap) {
            jwtClientConfiguration = (HashMap<String, String>) jwtClientAuthentication;
        }
        return jwtClientConfiguration;
    }

    public boolean validateClientJwt(Map<String, String[]> requestParameters, ClientJwtConfiguration clientJwtConfiguration, String clientId) {
        if (GRANT_TYPE.equals(UaaStringUtils.getSafeParameterValue(requestParameters.get(CLIENT_ASSERTION_TYPE)))) {
            try {
                String clientAssertion = UaaStringUtils.getSafeParameterValue(requestParameters.get(CLIENT_ASSERTION));
                JWT clientJWT = parseClientAssertion(clientAssertion);
                JWTClaimsSet clientClaims = getJWTClaimsSet(clientJWT);
                // Check if OIDC compliant client_assertion: client_id (from request) == sub (client_assertion) == iss (client_assertion)
                if (clientId.equals(getClientIdOidcAssertion(clientClaims))) {
                    // Validate token according to private_key_jwt with OIDC
                    return clientId.equals(validateClientJWToken(clientJWT, oidcMetadataFetcher == null ? new JWKSet() :
                                    JWKSet.parse(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration).getKeySetMap()),
                            clientId, clientId, keyInfoService.getTokenEndpointUrl()).getSubject());
                } else {
                    // Check if we found trust for private_key_jwt with RFC 7523. We allow client_id (from request) != sub (client_assertion)
                    ClientJwtCredential jwtFederation = getClientJwtFederation(clientJwtConfiguration, clientClaims);
                    if (jwtFederation != null) {
                        return validateFederatedClientWT(clientJWT, clientClaims, jwtFederation);
                    }
                    throw new BadCredentialsException("Wrong client_assertion");
                }
            } catch (ParseException | URISyntaxException | InvalidTokenException | OidcMetadataFetchingException e) {
                throw new BadCredentialsException("Bad client_assertion", e);
            }
        }
        return false;
    }

    private static ClientJwtCredential getClientJwtFederation(ClientJwtConfiguration clientJwtConfiguration,
                                                              JWTClaimsSet clientClaims) {
        if (clientJwtConfiguration.getClientJwtCredentials() == null) {
            return null;
        }
        return clientJwtConfiguration.getClientJwtCredentials().stream().filter(e ->
                e.getSubject().equals(clientClaims.getSubject()) &&
                e.getIssuer().equals(clientClaims.getIssuer()) &&
                isAudienceSupported(e.getAudience(), clientClaims.getAudience())).findFirst().orElse(null);
    }

    private static boolean isAudienceSupported(String audience, List<String> audList) {
        return audience == null || ObjectUtils.isEmpty(audList) || audList.contains(audience);
    }

    private static JWT parseClientAssertion(String clientAssertion) throws ParseException {
        return JWTParser.parse(clientAssertion);
    }

    private static JWTClaimsSet getJWTClaimsSet(JWT clientJWT) throws ParseException {
        return clientJWT != null ? clientJWT.getJWTClaimsSet() : null;
    }

    private static String getClientIdOidcAssertion(JWTClaimsSet clientToken) {
        if (clientToken != null && clientToken.getSubject() != null && clientToken.getIssuer() != null &&
                clientToken.getSubject().equals(clientToken.getIssuer()) && clientToken.getAudience() != null && clientToken.getJWTID() != null &&
                clientToken.getExpirationTime() != null) {
            // required claims, e.g. https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
            return clientToken.getSubject();
        }
        return null;
    }

    public static String getClientIdOidcAssertion(String clientAssertion) {
        try {
            return getClientIdOidcAssertion(getJWTClaimsSet(parseClientAssertion(clientAssertion)));
        } catch (ParseException e) {
            throw new BadCredentialsException("Bad client_assertion", e);
        }
    }

    private boolean validateFederatedClientWT(JWT jwtAssertion, JWTClaimsSet clientClaims, ClientJwtCredential jwtFederation) throws OidcMetadataFetchingException, ParseException {
        try {
            JWKSet jwkSet = retrieveJwkSet(clientClaims);
            String expectedAud = Optional.ofNullable(jwtFederation.getAudience()).orElse(keyInfoService.getTokenEndpointUrl());
            return validateClientJWToken(jwtAssertion, jwkSet, jwtFederation.getSubject(), jwtFederation.getIssuer(), expectedAud) != null;
        } catch (MalformedURLException | IllegalArgumentException | URISyntaxException e) {
            return false;
        }
    }

    private JWKSet getUaaJWKSet() throws ParseException {
        Map<String, KeyInfo> keyInfoMap = keyInfoService.getKeys();
        List<JWK> jwkList = new ArrayList<>(keyInfoMap.size());
        for (KeyInfo entry : keyInfoMap.values()) {
            jwkList.add(JWK.parse(entry.getJwkMap()));
        }
        return new JWKSet(jwkList);
    }

    private JWKSet getTrustedJwksSet(String issuer) throws OidcMetadataFetchingException, ParseException, MalformedURLException {
        OIDCIdentityProviderDefinition def = null;
        try {
            IdentityProvider<?> idp = externalOAuthAuthenticationManager.retrieveRegisteredIdentityProviderByIssuer(issuer);
            if (idp.getConfig() instanceof OIDCIdentityProviderDefinition oidcDefinition) {
                def = oidcDefinition;
            }
        } catch (DataRetrievalFailureException dataRetrievalFailureException) {
            // ignore, but retrieve trust by OIDC compliant issuer
        }
        if (def == null) {
            def = new OIDCIdentityProviderDefinition();
            def.setIssuer(issuer);
            def.setSkipSslValidation(false);
            // Allow only OIDC compliant issuer and create from it the so-called discovery URL, e.g., https://openid.net/specs/openid-connect-discovery-1_0.html
            if (!UaaUrlUtils.isUrl(issuer)) {
                throw new MalformedURLException(issuer + " is not a valid HTTP URL");
            }
            def.setDiscoveryUrl(UriComponentsBuilder.fromUriString(issuer).scheme("https").path("/.well-known/openid-configuration").build().toUri().toURL());
            oidcMetadataFetcher.fetchMetadataAndUpdateDefinition(def);
        }
        // fetch JSON Web Key Set now from trusted OIDCIdentityProviderDefinition or online
        JsonWebKeySet<JsonWebKey> tokenKeyFromOAuth = externalOAuthAuthenticationManager.getTokenKeyFromOAuth(def);
        return JWKSet.parse(tokenKeyFromOAuth.getKeySetMap());
    }

    private JWKSet retrieveJwkSet(JWTClaimsSet clientClaims) throws MalformedURLException, OidcMetadataFetchingException, ParseException {
        if (externalOAuthAuthenticationManager.idTokenWasIssuedByTheUaa(clientClaims.getIssuer())) {
            return getUaaJWKSet();
        } else {
            return getTrustedJwksSet(clientClaims.getIssuer());
        }
    }

    private JWTClaimsSet validateClientJWToken(JWT jwtAssertion, JWKSet jwkSet, String expectedSub, String expectIss, String expectedAud) {
        if (Optional.ofNullable(jwkSet).orElse(new JWKSet()).isEmpty()) {
            throw new BadCredentialsException("Bad empty jwk_set");
        }
        Algorithm algorithm = jwtAssertion.getHeader().getAlgorithm();
        if (!(algorithm instanceof JWSAlgorithm) || NOT_SUPPORTED_ALGORITHMS.contains(algorithm)) {
            throw new BadCredentialsException("Bad client_assertion algorithm");
        }
        JWKSource<SecurityContext> keySource = new ImmutableJWKSet<>(jwkSet);
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>((JWSAlgorithm) algorithm, keySource);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(keySelector);

        JWTClaimsSet.Builder claimSetBuilder = new JWTClaimsSet.Builder().issuer(expectIss).subject(expectedSub);
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(expectedAud, claimSetBuilder.build(), JWT_REQUIRED_CLAIMS));

        try {
            return jwtProcessor.process(jwtAssertion, null);
        } catch (BadJWSException | BadJWTException jwtException) { // signature failed
            throw new BadCredentialsException("Unauthorized client_assertion", jwtException);
        } catch (BadJOSEException | JOSEException e) { // key resolution, structure of JWT failed
            throw new BadCredentialsException("Untrusted client_assertion", e);
        }
    }

    private static KeyInfo loadKeyInfo(
            KeyInfoService keyInfoService,
            HashMap<String, String> jwtClientConfiguration,
            String kid,
            final boolean allowDynamicValueLookupInCustomZone
    ) {
        KeyInfo keyInfo;
        String signingKey = readJwtClientOption(jwtClientConfiguration.get("key"), null, allowDynamicValueLookupInCustomZone);
        if (signingKey == null) {
            keyInfo = Optional.ofNullable(keyInfoService.getKey(kid)).orElseThrow(() -> new BadCredentialsException("Missing requested signing key"));
        } else {
            String signingAlg = readJwtClientOption(jwtClientConfiguration.get("alg"), JWSAlgorithm.RS256.getName(), allowDynamicValueLookupInCustomZone);
            String signingCert = readJwtClientOption(jwtClientConfiguration.get("cert"), null, allowDynamicValueLookupInCustomZone);
            keyInfo = KeyInfoBuilder.build(kid, signingKey, UaaStringUtils.DEFAULT_UAA_URL, signingAlg, signingCert);
        }
        return keyInfo;
    }

    private static String readJwtClientOption(
            String jwtClientOption,
            String defaultOption,
            final boolean allowDynamicValueLookupInCustomZone
    ) {
        String value;
        if (isNotEmpty(jwtClientOption)) {
            // check if dynamic value means, a reference to another section in uaa yaml is defined
            Matcher matcher = getDynamicValueMatcher(jwtClientOption);
            if (matcher.find()) {
                value = Optional.ofNullable(getDynamicValue(matcher, allowDynamicValueLookupInCustomZone)).orElse(getDefaultValue(matcher));
            } else {
                value = jwtClientOption;
            }
        } else {
            value = defaultOption;
        }
        return value;
    }

    private static Matcher getDynamicValueMatcher(String value) {
        return DYNAMIC_VALUE_PARAMETER_PATTERN.matcher(value);
    }

    private static String getDynamicValue(Matcher m, final boolean allowLookupInCustomZone) {
        ApplicationContext applicationContext = ApplicationContextProvider.getApplicationContext();
        /* return a reference from application environment only if in default zone */
        final boolean isLookupAllowedInCurrentZone = new IdentityZoneManagerImpl().isCurrentZoneUaa() || allowLookupInCustomZone;
        if (applicationContext == null || !isLookupAllowedInCurrentZone) {
            return null;
        }
        return Optional.ofNullable(applicationContext.getEnvironment().getProperty(m.group("name"))).orElseThrow(() -> new BadCredentialsException("Missing referenced signing entry"));
    }

    private static String getDefaultValue(Matcher m) {
        return m.group("default");
    }
}
