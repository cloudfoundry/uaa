package org.cloudfoundry.identity.uaa.scim;

import java.io.IOException;
import java.util.regex.Pattern;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.web.filter.OncePerRequestFilter;

public class DisableInternalUserManagementFilter extends OncePerRequestFilter {

  public static final String DISABLE_INTERNAL_USER_MANAGEMENT = "disableInternalUserManagement";
  private static final String regex = "^/login|^/Users.*";
  private final IdentityProviderProvisioning identityProviderProvisioning;
  private final IdentityZoneManager identityZoneManager;
  private final Pattern pattern = Pattern.compile(regex);

  public DisableInternalUserManagementFilter(
      final IdentityProviderProvisioning identityProviderProvisioning,
      final IdentityZoneManager identityZoneManager) {
    this.identityProviderProvisioning = identityProviderProvisioning;
    this.identityZoneManager = identityZoneManager;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    if (matches(request)) {
      IdentityProvider idp =
          identityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(
              OriginKeys.UAA, identityZoneManager.getCurrentIdentityZoneId());
      boolean isDisableInternalUserManagement = false;
      UaaIdentityProviderDefinition config =
          ObjectUtils.castInstance(idp.getConfig(), UaaIdentityProviderDefinition.class);
      if (config != null) {
        isDisableInternalUserManagement = config.isDisableInternalUserManagement();
      }
      request.setAttribute(DISABLE_INTERNAL_USER_MANAGEMENT, isDisableInternalUserManagement);
    }

    filterChain.doFilter(request, response);
  }

  private boolean matches(HttpServletRequest request) {
    if (request.getContextPath() != null && request.getContextPath().length() > 0) {
      return pattern.matcher(request.getServletPath()).matches();
    }
    return pattern.matcher(request.getRequestURI()).matches();
  }
}
