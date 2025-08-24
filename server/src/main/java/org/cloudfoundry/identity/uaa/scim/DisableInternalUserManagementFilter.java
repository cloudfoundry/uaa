package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Pattern;

public class DisableInternalUserManagementFilter extends OncePerRequestFilter {

    public static final String DISABLE_INTERNAL_USER_MANAGEMENT = "disableInternalUserManagement";
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final IdentityZoneManager identityZoneManager;

    private static final String regex = "^/login|^/Users.*";

    private final Pattern pattern = Pattern.compile(regex);

    public DisableInternalUserManagementFilter(
            final IdentityProviderProvisioning identityProviderProvisioning,
            final IdentityZoneManager identityZoneManager) {
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (matches(request)) {
            IdentityProvider idp = identityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, identityZoneManager.getCurrentIdentityZoneId());
            boolean isDisableInternalUserManagement = false;
            UaaIdentityProviderDefinition config = ObjectUtils.castInstance(idp.getConfig(), UaaIdentityProviderDefinition.class);
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
