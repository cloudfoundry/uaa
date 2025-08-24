package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;

@Component
public class ExternalOAuthLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExternalOAuthLogoutSuccessHandler.class);

    private final IdentityProviderProvisioning providerProvisioning;
    private final OidcMetadataFetcher oidcMetadataFetcher;
    private final IdentityZoneManager identityZoneManager;
    private final Set<String> defaultOrigin = Set.of(OriginKeys.UAA, OriginKeys.LDAP);

    public ExternalOAuthLogoutSuccessHandler(
            @Qualifier("externalOAuthProviderConfigurator") final IdentityProviderProvisioning providerProvisioning,
            final OidcMetadataFetcher oidcMetadataFetcher,
            final IdentityZoneManager identityZoneManager) {
        this.providerProvisioning = providerProvisioning;
        this.oidcMetadataFetcher = oidcMetadataFetcher;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    protected String determineTargetUrl(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) {
        final AbstractExternalOAuthIdentityProviderDefinition<OIDCIdentityProviderDefinition> oauthConfig =
                this.getOAuthProviderForAuthentication(authentication);
        final String logoutUrl = this.getLogoutUrl(oauthConfig);

        if (logoutUrl == null) {
            final String defaultUrl = getZoneDefaultUrl();
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn("OAuth logout null, use default: %s".formatted(defaultUrl));
            }
            return defaultUrl;
        }

        return this.constructOAuthProviderLogoutUrl(request, logoutUrl, oauthConfig, authentication);
    }

    public String constructOAuthProviderLogoutUrl(final HttpServletRequest request, final String logoutUrl,
            final AbstractExternalOAuthIdentityProviderDefinition<OIDCIdentityProviderDefinition> oauthConfig,
            final Authentication authentication) {
        final StringBuilder oauthLogoutUriBuilder = new StringBuilder(request.getRequestURL());
        if (StringUtils.hasText(request.getQueryString())) {
            oauthLogoutUriBuilder.append("?");
            oauthLogoutUriBuilder.append(request.getQueryString());
        }
        final String oauthLogoutUri = URLEncoder.encode(oauthLogoutUriBuilder.toString(), StandardCharsets.UTF_8);

        String idTokenHint = "";
        if (authentication instanceof UaaAuthentication uaaAuthentication && uaaAuthentication.getIdpIdToken() != null) {
            idTokenHint = "&id_token_hint=%s".formatted(uaaAuthentication.getIdpIdToken());
        }

        return "%s?post_logout_redirect_uri=%s&client_id=%s%s".formatted(logoutUrl, oauthLogoutUri, oauthConfig.getRelyingPartyId(), idTokenHint);
    }

    public String getLogoutUrl(final AbstractExternalOAuthIdentityProviderDefinition<OIDCIdentityProviderDefinition> oAuthIdentityProviderDefinition) {
        String logoutUrl = null;
        if (oAuthIdentityProviderDefinition != null && oAuthIdentityProviderDefinition.getLogoutUrl() != null) {
            logoutUrl = oAuthIdentityProviderDefinition.getLogoutUrl().toString();
        } else {
            if (oAuthIdentityProviderDefinition instanceof OIDCIdentityProviderDefinition oidcIdentityProviderDefinition) {
                try {
                    this.oidcMetadataFetcher.fetchMetadataAndUpdateDefinition(oidcIdentityProviderDefinition);
                } catch (final OidcMetadataFetchingException e) {
                    LOGGER.warn(e.getLocalizedMessage(), e);
                }
                if (oidcIdentityProviderDefinition.getLogoutUrl() != null) {
                    logoutUrl = oidcIdentityProviderDefinition.getLogoutUrl().toString();
                }
            }
        }
        return logoutUrl;
    }

    public AbstractExternalOAuthIdentityProviderDefinition<OIDCIdentityProviderDefinition> getOAuthProviderForAuthentication(final Authentication authentication) {
        if (this.isExternalOAuthAuthentication(authentication)) {
            final UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
            final IdentityProvider<? extends AbstractIdentityProviderDefinition> identityProvider =
                    providerProvisioning.retrieveByOrigin(principal.getOrigin(), principal.getZoneId());
            if (identityProvider != null && identityProvider.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition && (
                    OriginKeys.OIDC10.equals(identityProvider.getType()) || OriginKeys.OAUTH20.equals(identityProvider.getType()))) {
                return (AbstractExternalOAuthIdentityProviderDefinition) identityProvider.getConfig();
            }
        }
        return null;
    }

    private boolean isExternalOAuthAuthentication(final Authentication authentication) {
        if (authentication instanceof UaaAuthentication uaaAuthentication && authentication.getPrincipal() instanceof UaaPrincipal principal) {
            final String origin = principal.getOrigin();
            return !this.defaultOrigin.contains(origin) &&
                    uaaAuthentication.getAuthenticationMethods() != null &&
                    uaaAuthentication.getAuthenticationMethods().contains("oauth");
        }
        return false;
    }

    private String getZoneDefaultUrl() {
        IdentityZoneConfiguration config = identityZoneManager.getCurrentIdentityZone().getConfig();
        if (config == null) {
            config = new IdentityZoneConfiguration();
        }
        return config.getLinks().getLogout().getRedirectUrl();
    }

    public boolean getPerformRpInitiatedLogout(AbstractExternalOAuthIdentityProviderDefinition<OIDCIdentityProviderDefinition> oauthConfig) {
        if (oauthConfig == null) {
            return false;
        }
        return oauthConfig.isPerformRpInitiatedLogout();
    }
}
