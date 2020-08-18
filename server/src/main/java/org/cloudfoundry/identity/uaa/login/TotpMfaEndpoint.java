package org.cloudfoundry.identity.uaa.login;

import com.google.zxing.WriterException;
import com.warrenstrange.googleauth.GoogleAuthenticatorException;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.CommonLoginPolicy;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa.MfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mfa.UserGoogleMfaCredentials;
import org.cloudfoundry.identity.uaa.mfa.UserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Controller
@SessionAttributes("uaaMfaCredentials")
@RequestMapping("/login/mfa")
public class TotpMfaEndpoint implements ApplicationEventPublisherAware {

    private final UserGoogleMfaCredentialsProvisioning mfaCredentialsProvisioning;
    private final MfaProviderProvisioning mfaProviderProvisioning;
    private Logger logger = LoggerFactory.getLogger(TotpMfaEndpoint.class);

    private final String mfaCompleteUrl;
    private ApplicationEventPublisher eventPublisher;
    private final UaaUserDatabase userDatabase;
    private final CommonLoginPolicy mfaPolicy;

    public TotpMfaEndpoint(
            final UserGoogleMfaCredentialsProvisioning mfaCredentialsProvisioning,
            final MfaProviderProvisioning mfaProviderProvisioning,
            final @Qualifier("mfaCompleteUrl") String mfaCompleteUrl,
            final UaaUserDatabase userDatabase,
            final @Qualifier("mfaGlobalUserLoginPolicy") CommonLoginPolicy mfaPolicy) {
        this.mfaCredentialsProvisioning = mfaCredentialsProvisioning;
        this.mfaProviderProvisioning = mfaProviderProvisioning;
        this.mfaCompleteUrl = mfaCompleteUrl;
        this.userDatabase = userDatabase;
        this.mfaPolicy = mfaPolicy;
    }

    @ModelAttribute("uaaMfaCredentials")
    public UserGoogleMfaCredentials getUaaMfaCredentials() throws UaaPrincipalIsNotInSession {
        UaaPrincipal principal = getSessionAuthPrincipal();
        UserGoogleMfaCredentials result = mfaCredentialsProvisioning.getUserGoogleMfaCredentials(principal.getId());
        if (result == null) {
            result = mfaCredentialsProvisioning.createUserCredentials(principal.getId());
            result.setMfaProviderId(getMfaProvider().getId());
        }
        return result;
    }

    @RequestMapping(value = {"/register"}, method = RequestMethod.GET)
    public String generateQrUrl(Model model,
                                @ModelAttribute("uaaMfaCredentials") UserGoogleMfaCredentials credentials)
      throws WriterException, IOException, UaaPrincipalIsNotInSession {
        UaaPrincipal uaaPrincipal = getSessionAuthPrincipal();
        MfaProvider provider = getMfaProvider();
        if (mfaCredentialsProvisioning.activeUserCredentialExists(uaaPrincipal.getId(), provider.getId())) {
            return "redirect:/login/mfa/verify";
        } else {
            String url = mfaCredentialsProvisioning.getOtpAuthURL(provider.getConfig().getIssuer(), credentials, uaaPrincipal.getName());
            model.addAttribute("qrurl", url);
            model.addAttribute("identity_zone", IdentityZoneHolder.get().getName());
            return "mfa/qr_code";
        }
    }

    @RequestMapping(value = {"/manual"}, method = RequestMethod.GET)
    public String manualRegistration(
      Model model,
      @ModelAttribute("uaaMfaCredentials") UserGoogleMfaCredentials credentials
    ) throws UaaPrincipalIsNotInSession {
        UaaPrincipal uaaPrincipal = getSessionAuthPrincipal();
        MfaProvider provider = getMfaProvider();

        if (mfaCredentialsProvisioning.activeUserCredentialExists(uaaPrincipal.getId(), provider.getId())) {
            return "redirect:/login/mfa/verify";
        } else {
            model.addAttribute("issuer", provider.getConfig().getIssuer());
            model.addAttribute("username", uaaPrincipal.getName());
            model.addAttribute("mfa_secret", credentials.getSecretKey());
            model.addAttribute("identity_zone", IdentityZoneHolder.get().getName());
            return "mfa/manual_registration";
        }

    }

    @RequestMapping(value = {"/verify"}, method = RequestMethod.GET)
    public ModelAndView totpAuthorize(Model model) throws UaaPrincipalIsNotInSession {
        UaaPrincipal uaaPrincipal = getSessionAuthPrincipal();
        return renderEnterCodePage(model, uaaPrincipal);

    }

    @RequestMapping(value = {"/verify.do"}, method = RequestMethod.POST)
    public ModelAndView validateCode(Model model,
                                     @RequestParam("code") String code,
                                     @ModelAttribute("uaaMfaCredentials") UserGoogleMfaCredentials credentials,
                                     HttpServletRequest request,
                                     SessionStatus sessionStatus)
      throws UaaPrincipalIsNotInSession {
        UaaAuthentication uaaAuth = getUaaAuthentication();
        UaaPrincipal uaaPrincipal = getSessionAuthPrincipal();

        if (!this.mfaPolicy.isAllowed(uaaPrincipal.getId()).isAllowed()) {
            throw new AuthenticationPolicyRejectionException("Your account has been locked because of too many failed attempts to login.");
        }

        try {
            Integer codeValue = Integer.valueOf(code);
            if (mfaCredentialsProvisioning.isValidCode(credentials, codeValue)) {
                if (mfaCredentialsProvisioning.getUserGoogleMfaCredentials(uaaPrincipal.getId()) == null) {
                    mfaCredentialsProvisioning.saveUserCredentials(credentials);
                }
                Set<String> authMethods = new HashSet<>(uaaAuth.getAuthenticationMethods());
                authMethods.addAll(Arrays.asList("otp", "mfa"));
                uaaAuth.setAuthenticationMethods(authMethods);
                publish(new MfaAuthenticationSuccessEvent(getUaaUser(uaaPrincipal), uaaAuth, getMfaProvider().getType().toValue(), IdentityZoneHolder.getCurrentZoneId()));
                sessionStatus.setComplete();
                SessionUtils.setSecurityContext(request.getSession(), SecurityContextHolder.getContext());
                return new ModelAndView(new RedirectView(mfaCompleteUrl, true));
            }
            logger.debug("Code authorization failed for user: " + uaaPrincipal.getId());
            publish(new MfaAuthenticationFailureEvent(getUaaUser(uaaPrincipal), uaaAuth, getMfaProvider().getType().toValue(), IdentityZoneHolder.getCurrentZoneId()));
            model.addAttribute("error", "Incorrect code, please try again.");
        } catch (NumberFormatException | GoogleAuthenticatorException e) {
            logger.debug("Error validating the code for user: " + uaaPrincipal.getId() + ". Error: " + e.getMessage());
            publish(new MfaAuthenticationFailureEvent(getUaaUser(uaaPrincipal), uaaAuth, getMfaProvider().getType().toValue(), IdentityZoneHolder.getCurrentZoneId()));
            model.addAttribute("error", "Incorrect code, please try again.");
        }
        return renderEnterCodePage(model, uaaPrincipal);
    }

    @ExceptionHandler(UaaPrincipalIsNotInSession.class)
    public ModelAndView handleUaaPrincipalIsNotInSession() {
        return new ModelAndView("redirect:/login", Collections.emptyMap());
    }

    @ExceptionHandler(AuthenticationPolicyRejectionException.class)
    public ModelAndView handleMFALockedOut() {
        SecurityContextHolder.getContext().setAuthentication(null);

        return new ModelAndView("redirect:/login?error=account_locked", Collections.emptyMap());
    }

    private ModelAndView renderEnterCodePage(Model model, UaaPrincipal uaaPrincipal) {
        model.addAttribute("is_first_time_user", mfaCredentialsProvisioning.isFirstTimeMFAUser(uaaPrincipal));
        model.addAttribute("identity_zone", IdentityZoneHolder.get().getName());
        return new ModelAndView("mfa/enter_code", model.asMap());
    }

    private UaaPrincipal getSessionAuthPrincipal() throws UaaPrincipalIsNotInSession {
        UaaAuthentication uaaAuth = getUaaAuthentication();
        if (uaaAuth != null) {
            UaaPrincipal principal = uaaAuth.getPrincipal();
            if (principal != null) {
                return principal;
            }
        }
        throw new UaaPrincipalIsNotInSession();
    }

    private UaaAuthentication getUaaAuthentication() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        return a instanceof UaaAuthentication ? (UaaAuthentication) a : null;
    }

    private MfaProvider getMfaProvider() {
        String providerName = IdentityZoneHolder.get().getConfig().getMfaConfig().getProviderName();
        return mfaProviderProvisioning.retrieveByName(providerName, IdentityZoneHolder.get().getId());
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher;
    }

    private void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    private UaaUser getUaaUser(UaaPrincipal principal) {
        try {
            UaaUser user = userDatabase.retrieveUserByName(principal.getName(), principal.getOrigin());
            if (user != null) {
                return user;
            }
        } catch (UsernameNotFoundException ignored) {
        }
        return null;
    }

    public class UaaPrincipalIsNotInSession extends Exception {
    }
}
