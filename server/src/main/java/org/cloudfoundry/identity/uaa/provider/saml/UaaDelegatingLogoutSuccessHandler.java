package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.authentication.ZoneAwareWhitelistLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthLogoutSuccessHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2RelyingPartyInitiatedLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * UaaDelegatingLogoutSuccessHandler is a {@link LogoutSuccessHandler} that delegates to the appropriate
 * logout handler based on the authentication.
 * <p>
 * <li>If we have a valid SAML2 {@link Saml2AuthenticatedPrincipal} in the authentication, and have a
 * SingleLogoutServiceLocation set, then we will delegate to the {@link Saml2RelyingPartyInitiatedLogoutSuccessHandler}.
 * <li> If we have a valid OAuth2 {@link AbstractExternalOAuthIdentityProviderDefinition} in the authentication,
 * then we will delegate to the {@link ExternalOAuthLogoutSuccessHandler}.
 * <li> Otherwise, we will delegate to the {@link ZoneAwareWhitelistLogoutSuccessHandler}.
 * <p>
 * On the LogoutResponse side, there is no Authentication available at that point, so will
 * always delegate to the {@link ZoneAwareWhitelistLogoutSuccessHandler}.
 */
@Component
public class UaaDelegatingLogoutSuccessHandler implements LogoutSuccessHandler {
    private final ZoneAwareWhitelistLogoutSuccessHandler zoneAwareWhitelistLogoutHandler;
    private final Saml2RelyingPartyInitiatedLogoutSuccessHandler saml2RelyingPartyInitiatedLogoutSuccessHandler;
    private final ExternalOAuthLogoutSuccessHandler externalOAuthLogoutHandler;
    private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

    public UaaDelegatingLogoutSuccessHandler(ZoneAwareWhitelistLogoutSuccessHandler zoneAwareWhitelistLogoutHandler,
            Saml2RelyingPartyInitiatedLogoutSuccessHandler saml2RelyingPartyInitiatedLogoutSuccessHandler,
            ExternalOAuthLogoutSuccessHandler externalOAuthLogoutHandler,
            RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
        this.zoneAwareWhitelistLogoutHandler = zoneAwareWhitelistLogoutHandler;
        this.saml2RelyingPartyInitiatedLogoutSuccessHandler = saml2RelyingPartyInitiatedLogoutSuccessHandler;
        this.externalOAuthLogoutHandler = externalOAuthLogoutHandler;
        this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (shouldPerformSamlRelyingPartyLogout(request, authentication)) {
            saml2RelyingPartyInitiatedLogoutSuccessHandler.onLogoutSuccess(request, response, authentication);
            return;
        }

        if (shouldPerformOAuthRpInitiatedLogout(authentication)) {
            externalOAuthLogoutHandler.onLogoutSuccess(request, response, authentication);
            return;
        }

        zoneAwareWhitelistLogoutHandler.onLogoutSuccess(request, response, authentication);
    }

    private boolean shouldPerformOAuthRpInitiatedLogout(Authentication authentication) {

        AbstractExternalOAuthIdentityProviderDefinition<OIDCIdentityProviderDefinition> oauthConfig = externalOAuthLogoutHandler.getOAuthProviderForAuthentication(authentication);
        String logoutUrl = externalOAuthLogoutHandler.getLogoutUrl(oauthConfig);
        boolean shouldPerformRpInitiatedLogout = externalOAuthLogoutHandler.getPerformRpInitiatedLogout(oauthConfig);
        return shouldPerformRpInitiatedLogout && logoutUrl != null;
    }

    /**
     * Determines if the logout should follow the SAML protocol to the Asserting Party.
     */
    private boolean shouldPerformSamlRelyingPartyLogout(HttpServletRequest request, Authentication authentication) {
        if (authentication == null) {
            return false;
        }

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof Saml2AuthenticatedPrincipal samlPrincipal)) {
            return false;
        }

        String registrationId = samlPrincipal.getRelyingPartyRegistrationId();
        if (registrationId == null) {
            return false;
        }

        RelyingPartyRegistration registration = relyingPartyRegistrationResolver.resolve(request, registrationId);
        if (registration == null) {
            return false;
        }

        String singleLogoutServiceLocation = Optional.ofNullable(registration.getAssertingPartyDetails()).map(RelyingPartyRegistration.AssertingPartyDetails::getSingleLogoutServiceLocation).orElse(null);
        return singleLogoutServiceLocation != null;
    }
}
