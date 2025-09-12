package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.S256PkceVerifier;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.UaaRandomStringUtil;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.CollectionUtils;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;

public class ExternalOAuthProviderConfigurator implements IdentityProviderProvisioning {

    private static Logger LOGGER = LoggerFactory.getLogger(ExternalOAuthProviderConfigurator.class);

    private final IdentityProviderProvisioning providerProvisioning;
    private final OidcMetadataFetcher oidcMetadataFetcher;
    private final UaaRandomStringUtil uaaRandomStringUtil;

    public ExternalOAuthProviderConfigurator(
            final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning providerProvisioning,
            final OidcMetadataFetcher oidcMetadataFetcher,
            final UaaRandomStringUtil uaaRandomStringUtil) {
        this.providerProvisioning = providerProvisioning;
        this.oidcMetadataFetcher = oidcMetadataFetcher;
        this.uaaRandomStringUtil = uaaRandomStringUtil;
    }

    protected OIDCIdentityProviderDefinition overlay(OIDCIdentityProviderDefinition definition) {
        try {
            oidcMetadataFetcher.fetchMetadataAndUpdateDefinition(definition);
            return definition;
        } catch (OidcMetadataFetchingException e) {
            throw new IllegalStateException(e);
        }
    }

    public String getIdpAuthenticationUrl(
            final AbstractExternalOAuthIdentityProviderDefinition definition,
            final String idpOriginKey,
            final HttpServletRequest request) {
        var idpUrlBase = getIdpUrlBase(definition);
        var callbackUrl = getCallbackUrlForIdp(idpOriginKey, UaaUrlUtils.getBaseURL(request));
        var responseType = URLEncoder.encode(definition.getResponseType(), StandardCharsets.UTF_8);
        var relyingPartyId = definition.getRelyingPartyId();

        var state = generateStateParam();
        SessionUtils.setStateParam(request.getSession(), SessionUtils.stateParameterAttributeKeyForIdp(idpOriginKey), state);

        UriComponentsBuilder uriBuilder = UriComponentsBuilder
                .fromUriString(idpUrlBase)
                .queryParam("client_id", relyingPartyId)
                .queryParam("response_type", responseType)
                .queryParam("redirect_uri", callbackUrl)
                .queryParam("state", state);

        // no client-secret, switch to PKCE and treat client as public, same logic is implemented in spring security
        // https://docs.spring.io/spring-security/site/docs/5.3.1.RELEASE/reference/html5/#initiating-the-authorization-request
        if (definition.getRelyingPartySecret() == null) {
            var pkceVerifier = new S256PkceVerifier();
            var codeVerifier = generateCodeVerifier();
            var codeChallenge = pkceVerifier.compute(codeVerifier);
            SessionUtils.setStateParam(request.getSession(), SessionUtils.codeVerifierParameterAttributeKeyForIdp(idpOriginKey), codeVerifier);
            uriBuilder.queryParam("code_challenge", codeChallenge);
            uriBuilder.queryParam("code_challenge_method", pkceVerifier.getCodeChallengeMethod());
        }

        if (!CollectionUtils.isEmpty(definition.getScopes())) {
            uriBuilder.queryParam("scope", URLEncoder.encode(String.join(" ", definition.getScopes()), StandardCharsets.UTF_8));
        }

        if (OIDCIdentityProviderDefinition.class.equals(definition.getParameterizedClass())) {
            var nonceGenerator = new RandomValueStringGenerator(12);
            uriBuilder.queryParam("nonce", nonceGenerator.generate());
        }

        return uriBuilder.build().toUriString();
    }

    private String generateStateParam() {
        return uaaRandomStringUtil.getSecureRandom(10);
    }

    private String generateCodeVerifier() {
        return uaaRandomStringUtil.getSecureRandom(128);
    }

    private String getCallbackUrlForIdp(String idpOriginKey, String uaaBaseUrl) {
        return URLEncoder.encode(uaaBaseUrl + "/login/callback/" + idpOriginKey, StandardCharsets.UTF_8);
    }

    private String getIdpUrlBase(final AbstractExternalOAuthIdentityProviderDefinition definition) {
        if (definition instanceof OIDCIdentityProviderDefinition) {
            return overlay((OIDCIdentityProviderDefinition) definition).getAuthUrl().toString();
        }
        return definition.getAuthUrl().toString();
    }

    @Override
    public IdentityProvider create(IdentityProvider identityProvider, String zoneId) {
        return providerProvisioning.create(identityProvider, zoneId);
    }

    @Override
    public IdentityProvider update(IdentityProvider identityProvider, String zoneId) {
        return providerProvisioning.update(identityProvider, zoneId);
    }

    @Override
    public IdentityProvider retrieve(String id, String zoneId) {
        IdentityProvider p = providerProvisioning.retrieve(id, zoneId);
        if (p != null && p.getType().equals(OIDC10)) {
            p.setConfig(overlay((OIDCIdentityProviderDefinition) p.getConfig()));
        }
        return p;
    }

    @Override
    public List<IdentityProvider> retrieveActive(String zoneId) {
        return retrieveAll(true, zoneId);
    }

    public IdentityProvider retrieveByIssuer(String issuer, String zoneId) throws IncorrectResultSizeDataAccessException {
        List<IdentityProvider> providers = retrieveAll(true, zoneId)
                .stream()
                .filter(p -> OIDC10.equals(p.getType()) &&
                        issuer.equals(((OIDCIdentityProviderDefinition) p.getConfig()).getIssuer()))
                .collect(Collectors.toList());
        if (providers.isEmpty()) {
            throw new IncorrectResultSizeDataAccessException(String.format("Active provider with issuer[%s] not found", issuer), 1);
        } else if (providers.size() > 1) {
            throw new IncorrectResultSizeDataAccessException(String.format("Duplicate providers with issuer[%s] not found", issuer), 1);
        }
        return providers.get(0);
    }

    @Override
    public List<IdentityProvider> retrieveAll(boolean activeOnly, String zoneId) {
        List<IdentityProvider> providers = providerProvisioning.retrieveAll(activeOnly, zoneId);
        return retrieveAll(providers);
    }

    public List<IdentityProvider> retrieveAll(List<IdentityProvider> providers) {
        final List<String> types = Arrays.asList(OAUTH20, OIDC10);
        List<IdentityProvider> overlayedProviders = new ArrayList<>();
        ofNullable(providers).orElse(emptyList()).stream()
                .filter(p -> types.contains(p.getType()))
                .forEach(p -> {
                    if (p.getType().equals(OIDC10)) {
                        try {
                            OIDCIdentityProviderDefinition overlayedDefinition = overlay((OIDCIdentityProviderDefinition) p.getConfig());
                            p.setConfig(overlayedDefinition);
                        } catch (Exception e) {
                            LOGGER.error("Identity provider excluded from login page due to a problem.", e);
                            return;
                        }
                    }
                    overlayedProviders.add(p);
                });
        return overlayedProviders;
    }

    @Override
    public IdentityProvider retrieveByOrigin(String origin, String zoneId) {
        IdentityProvider p = providerProvisioning.retrieveByOrigin(origin, zoneId);
        if (p != null && p.getType().equals(OIDC10)) {
            p.setConfig(overlay((OIDCIdentityProviderDefinition) p.getConfig()));
        }
        return p;
    }

    @Override
    public IdentityProvider retrieveByOriginIgnoreActiveFlag(String origin, String zoneId) {
        IdentityProvider p = providerProvisioning.retrieveByOriginIgnoreActiveFlag(origin, zoneId);
        if (p != null && p.getType().equals(OIDC10)) {
            p.setConfig(overlay((OIDCIdentityProviderDefinition) p.getConfig()));
        }
        return p;
    }
}
