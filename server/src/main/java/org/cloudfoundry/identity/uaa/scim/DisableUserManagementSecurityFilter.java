package org.cloudfoundry.identity.uaa.scim;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.cloudfoundry.identity.uaa.web.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class DisableUserManagementSecurityFilter extends OncePerRequestFilter {

    public static final String INTERNAL_USER_CREATION_IS_CURRENTLY_DISABLED = "Internal User Creation is currently disabled. External User Store is in use.";
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final IdentityZoneManager identityZoneManager;

    private static String regex1 = "";

    static {
        // scim user endpoints
        // ui controllers
        regex1 = "^/Users/.*/password";
        regex1 += "|^/Users/.*/verify";
        regex1 += "|^/create_account";
        regex1 += "|^/create_account.do";
        regex1 += "|^/accounts/email_sent";
        regex1 += "|^/verify_user";
        regex1 += "|^/change_email";
        regex1 += "|^/change_email.do";
        regex1 += "|^/verify_email";
        regex1 += "|^/change_password";
        regex1 += "|^/change_password.do";
        regex1 += "|^/forgot_password";
        regex1 += "|^/forgot_password.do";
        regex1 += "|^/email_sent";
        regex1 += "|^/reset_password";
        regex1 += "|^/reset_password.do";
    }

    private final Pattern pattern1 = Pattern.compile(regex1);
    private final List<String> methods1 = Arrays.asList("GET", "POST", "PUT", "DELETE");

    public DisableUserManagementSecurityFilter(
            final IdentityProviderProvisioning identityProviderProvisioning,
            final IdentityZoneManager identityZoneManager) {
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, final HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        try {
            if (matches(request)) {
                IdentityProvider idp = identityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, identityZoneManager.getCurrentIdentityZoneId());
                boolean isDisableInternalUserManagement = false;
                UaaIdentityProviderDefinition config = ObjectUtils.castInstance(idp.getConfig(), UaaIdentityProviderDefinition.class);
                if (config != null) {
                    isDisableInternalUserManagement = config.isDisableInternalUserManagement();
                }
                if (isDisableInternalUserManagement) {
                    throw new InternalUserManagementDisabledException(INTERNAL_USER_CREATION_IS_CURRENTLY_DISABLED);
                }
            }
            filterChain.doFilter(request, response);
        } catch (InternalUserManagementDisabledException x) {
            handleInternalUserManagementDisabledException(response, x);
        } catch (ServletException x) {
            if (x.getRootCause() instanceof InternalUserManagementDisabledException) {
                handleInternalUserManagementDisabledException(response, (InternalUserManagementDisabledException) x.getRootCause());
            } else {
                throw x;
            }
        }
    }

    private void handleInternalUserManagementDisabledException(HttpServletResponse response, InternalUserManagementDisabledException x) throws IOException {
        ExceptionReportHttpMessageConverter converter = new ExceptionReportHttpMessageConverter();
        response.setStatus(403);
        converter.write(new ExceptionReport(x), MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
    }

    private boolean matches(HttpServletRequest request) {
        return pattern1.matcher(getUri(request)).matches() && methods1.contains(request.getMethod());
    }

    private String getUri(HttpServletRequest request) {
        if (request.getContextPath() != null && request.getContextPath().length() > 0) {
            return request.getServletPath();
        }
        return request.getRequestURI();
    }
}
