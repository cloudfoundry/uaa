package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;

public class ExernalOAuthLogoutHandler extends SimpleUrlLogoutSuccessHandler {

  private static final Logger LOGGER = LoggerFactory.getLogger(ExernalOAuthLogoutHandler.class);

  private final IdentityProviderProvisioning providerProvisioning;
  private final OidcMetadataFetcher oidcMetadataFetcher;
  private final Set<String> defaultOrigin = Set.of(OriginKeys.UAA, OriginKeys.LDAP);

  public ExernalOAuthLogoutHandler(final IdentityProviderProvisioning providerProvisioning, final OidcMetadataFetcher oidcMetadataFetcher) {
    this.providerProvisioning = providerProvisioning;
    this.oidcMetadataFetcher = oidcMetadataFetcher;
  }

  @Override
  protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    AbstractExternalOAuthIdentityProviderDefinition oauthConfig = getOAuthProviderForAuthentication(authentication);
    String logoutUrl = getLogoutUrl(oauthConfig);

    if (logoutUrl == null) {
      String defaultUrl = getZoneDefaultUrl();
      LOGGER.warn(String.format("OAuth logout null, use default: %s", defaultUrl));
      return defaultUrl;
    }

    StringBuffer oauthLogoutUriBuilder = request.getRequestURL();
    if (StringUtils.hasText(request.getQueryString())) {
      oauthLogoutUriBuilder.append("?");
      oauthLogoutUriBuilder.append(request.getQueryString());
    }
    String oauthLogoutUri = URLEncoder.encode(oauthLogoutUriBuilder.toString(), StandardCharsets.UTF_8);
    StringBuilder sb = new StringBuilder(logoutUrl);
    sb.append("?post_logout_redirect_uri=");
    sb.append(oauthLogoutUri);
    sb.append("&client_id=");
    sb.append(oauthConfig.getRelyingPartyId());
    return sb.toString();
  }

  public boolean isExternalOAuthentication(Authentication authentication) {
    if (authentication != null && authentication.getPrincipal() instanceof UaaPrincipal) {
      UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
      String origin = principal.getOrigin();
      return !defaultOrigin.contains(origin);
    }
    return false;
  }

  private String getLogoutUrl(AbstractExternalOAuthIdentityProviderDefinition oAuthIdentityProviderDefinition) {
    if (oAuthIdentityProviderDefinition != null && oAuthIdentityProviderDefinition.getLogoutUrl() != null) {
      return oAuthIdentityProviderDefinition.getLogoutUrl().toString();
    } else {
      if (oAuthIdentityProviderDefinition instanceof OIDCIdentityProviderDefinition) {
        OIDCIdentityProviderDefinition oidcIdentityProviderDefinition = (OIDCIdentityProviderDefinition) oAuthIdentityProviderDefinition;
        try {
          oidcMetadataFetcher.fetchMetadataAndUpdateDefinition(oidcIdentityProviderDefinition);
          return oidcIdentityProviderDefinition.getLogoutUrl() != null ? oidcIdentityProviderDefinition.getLogoutUrl().toString() : null;
        } catch (OidcMetadataFetchingException e) {
          LOGGER.warn(e.getLocalizedMessage(), e);
        }
      }
    }
    return null;
  }

  private AbstractExternalOAuthIdentityProviderDefinition getOAuthProviderForAuthentication(Authentication authentication) {
    if (isExternalOAuthentication(authentication)) {
      UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
      String origin = principal.getOrigin();
      if (!defaultOrigin.contains(origin)) {
        IdentityProvider identityProvider = providerProvisioning.retrieveByOrigin(origin, principal.getZoneId());
        if (identityProvider != null && identityProvider.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition && (
            OriginKeys.OIDC10.equals(identityProvider.getType()) || OriginKeys.OAUTH20.equals(identityProvider.getType()))) {
          return (AbstractExternalOAuthIdentityProviderDefinition) identityProvider.getConfig();
        }
      }
    }
    return null;
  }

  private String getZoneDefaultUrl() {
    IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
    if (config == null) {
      config = new IdentityZoneConfiguration();
    }
    return config.getLinks().getLogout().getRedirectUrl();
  }
}
