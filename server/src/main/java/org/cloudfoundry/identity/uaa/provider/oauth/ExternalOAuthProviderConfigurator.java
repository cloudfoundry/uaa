package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.S256PkceVerifier;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.UaaRandomStringUtil;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.springframework.util.CollectionUtils;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;

public class ExternalOAuthProviderConfigurator implements IdentityProviderProvisioning {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExternalOAuthProviderConfigurator.class);

    private final IdentityProviderProvisioning providerProvisioning;
    private final OidcMetadataFetcher oidcMetadataFetcher;
    private final UaaRandomStringUtil uaaRandomStringUtil;
    private final IdentityZoneProvisioning identityZoneProvisioning;
    private final IdentityZoneManager identityZoneManager;

    public ExternalOAuthProviderConfigurator(
            final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning providerProvisioning,
            final OidcMetadataFetcher oidcMetadataFetcher,
            final UaaRandomStringUtil uaaRandomStringUtil,
            final @Qualifier("identityZoneProvisioning") IdentityZoneProvisioning identityZoneProvisioning,
            final IdentityZoneManager identityZoneManager
        ) {
        this.providerProvisioning = providerProvisioning;
        this.oidcMetadataFetcher = oidcMetadataFetcher;
        this.uaaRandomStringUtil = uaaRandomStringUtil;
        this.identityZoneProvisioning = identityZoneProvisioning;
        this.identityZoneManager = identityZoneManager;
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
        if (isPkceNeeded(definition)) {
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

            Map<String, String> additionalParameters = ofNullable(((OIDCIdentityProviderDefinition) definition).getAdditionalAuthzParameters()).orElse(emptyMap());
            additionalParameters.keySet().stream().forEach(e -> uriBuilder.queryParam(e, additionalParameters.get(e)));
        }

        return uriBuilder.build().toUriString();
    }

    protected static boolean isPkceNeeded(AbstractExternalOAuthIdentityProviderDefinition definition) {
        return definition.isPkce() || definition.getRelyingPartySecret() == null;
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
        if (definition instanceof OIDCIdentityProviderDefinition oidcIdentityProviderDefinition) {
            return overlay(oidcIdentityProviderDefinition).getAuthUrl().toString();
        }
        return definition.getAuthUrl().toString();
    }

    private boolean isOriginLoopAllowed(String zoneId, boolean allowed) {
        if (!allowed) {
            return false;
        }
        IdentityZoneConfiguration idzConfig;
        if (identityZoneManager.getCurrentIdentityZoneId().equals(zoneId)) {
            idzConfig = identityZoneManager.getCurrentIdentityZone().getConfig();
        } else {
            idzConfig = identityZoneProvisioning.retrieve(zoneId).getConfig();
        }
        return idzConfig == null || Optional.of(idzConfig.getUserConfig()).map(UserConfig::isAllowAllOrigins).orElse(true);
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
        IdentityProvider issuedProvider = null;
        boolean originLoopAllowed = true;
        try {
            issuedProvider = retrieveByExternId(issuer, OIDC10, zoneId);
            if (issuedProvider != null && issuedProvider.isActive()
                && issuedProvider.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition<?> oAuthIdentityProviderDefinition
                && oAuthIdentityProviderDefinition.getIssuer().equals(issuer)) {
                return issuedProvider;
            }
        } catch (EmptyResultDataAccessException e) {
            originLoopAllowed = isOriginLoopAllowed(zoneId, true);
            if (!isOriginLoopAllowed(zoneId, originLoopAllowed)) {
                throw new IncorrectResultSizeDataAccessException(String.format("No provider with unique issuer[%s] found", issuer), 1, 0, e);
            }
        }
        if (!isOriginLoopAllowed(zoneId, originLoopAllowed) && issuedProvider == null) {
            throw new IncorrectResultSizeDataAccessException(String.format("Active provider with unique issuer[%s] not found", issuer), 1);
        }
        List<IdentityProvider> providers = retrieveAll(true, zoneId)
                .stream()
                .filter(p -> OIDC10.equals(p.getType()) &&
                        issuer.equals(((OIDCIdentityProviderDefinition) p.getConfig()).getIssuer()))
                .toList();
        if (providers.isEmpty()) {
            throw new IncorrectResultSizeDataAccessException(String.format("Active provider with issuer[%s] not found", issuer), 1);
        } else if (providers.size() > 1) {
            throw new IncorrectResultSizeDataAccessException(String.format("Duplicate providers with issuer[%s] not found", issuer), 1);
        }
        return providers.get(0);
    }

    @Override
    public List<IdentityProvider> retrieveAll(boolean activeOnly, String zoneId) {
        final List<String> types = Arrays.asList(OAUTH20, OIDC10);
        List<IdentityProvider> providers = providerProvisioning.retrieveAll(activeOnly, zoneId);
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
    public IdentityProvider retrieveByExternId(String externId, String type, String zoneId) {
        IdentityProvider p = providerProvisioning.retrieveByExternId(externId, type, zoneId);
        if (p != null && OIDC10.equals(type)) {
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
