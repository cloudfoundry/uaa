package org.cloudfoundry.identity.uaa.login;

import com.warrenstrange.googleauth.GoogleAuthenticatorException;
import com.warrenstrange.googleauth.IGoogleAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mfa_provider.UserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.mfa_provider.GoogleAuthenticatorAdapter;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Controller
public class TotpEndpoint {
    public static final String MFA_VALIDATE_USER = "MFA_VALIDATE_USER";

    private IGoogleAuthenticator authenticator;
    private UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning;
    private MfaProviderProvisioning mfaProviderProvisioning;
    private Log logger = LogFactory.getLog(TotpEndpoint.class);

    private GoogleAuthenticatorAdapter googleAuthenticatorService = new GoogleAuthenticatorAdapter();

    @RequestMapping(value = {"/login/mfa/register"}, method = RequestMethod.GET)
    public String generateQrUrl(HttpSession session, Model model) throws NoSuchAlgorithmException, IOException {

         UaaPrincipal uaaPrincipal = getSessionAuthPrincipal(session);
         if(uaaPrincipal == null) return "redirect:/login";

        if(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(uaaPrincipal.getId())) {
            return "redirect:/login/mfa/verify";
        } else{
            String url = googleAuthenticatorService.getOtpAuthURL(authenticator, uaaPrincipal.getId(), uaaPrincipal.getName());
            MfaProvider provider = mfaProviderProvisioning.retrieve(IdentityZoneHolder.get().getConfig().getMfaConfig().getProviderId(), IdentityZoneHolder.get().getId());
            model.addAttribute("qrurl", url);
            model.addAttribute("mfa_provider", provider.getName());

            return "qr_code";
        }
    }

    @RequestMapping(value = {"/login/mfa/verify"}, method = RequestMethod.GET)
    public String totpAuthorize(HttpSession session, Model model) {
        UaaPrincipal uaaPrincipal = getSessionAuthPrincipal(session);
        if(uaaPrincipal == null) return "redirect:/login";
        model.addAttribute("is_first_time_user", userGoogleMfaCredentialsProvisioning.isFirstTimeMFAUser(uaaPrincipal));
        return "enter_code";
    }


    @RequestMapping(value = {"/login/mfa/verify.do"}, method = RequestMethod.POST)
    public String validateCode(Model model,
                               HttpSession session,
                               @RequestParam("code") String code)
            throws NoSuchAlgorithmException, IOException {
        UaaAuthentication sessionAuth = session.getAttribute(MFA_VALIDATE_USER) instanceof UaaAuthentication ? (UaaAuthentication) session.getAttribute(MFA_VALIDATE_USER) : null;
        UaaPrincipal uaaPrincipal;
        if(sessionAuth != null) {
            uaaPrincipal = sessionAuth.getPrincipal();
        } else {
            return "redirect:/login";
        }

        try {
            Integer codeValue = Integer.valueOf(code);
            if(authenticator.authorizeUser(uaaPrincipal.getId(), codeValue)) {
                userGoogleMfaCredentialsProvisioning.persistCredentials();
                session.removeAttribute(MFA_VALIDATE_USER);
                Set<String> authMethods = new HashSet<>(sessionAuth.getAuthenticationMethods());
                authMethods.addAll(Arrays.asList("otp", "mfa"));
                sessionAuth.setAuthenticationMethods(authMethods);
                SecurityContextHolder.getContext().setAuthentication(sessionAuth);
                return "home";
            }
            logger.debug("Code authorization failed for user: " + uaaPrincipal.getId());
            model.addAttribute("error", "Invalid QR code");
        } catch (NumberFormatException e) {
            logger.debug("Error validating the code for user: " + uaaPrincipal.getId() + ". Error: " + e.getMessage());
            model.addAttribute("error", "QR code can be number only");
        } catch (GoogleAuthenticatorException e) {
            logger.debug("Error validating the code for user: " + uaaPrincipal.getId() + ". Error: " + e.getMessage());
            model.addAttribute("error", "Invalid QR code");
        }
        model.addAttribute("is_first_time_user", userGoogleMfaCredentialsProvisioning.isFirstTimeMFAUser(uaaPrincipal));
        return "enter_code";
    }


    public void setAuthenticator(IGoogleAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    public void setUserGoogleMfaCredentialsProvisioning(UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning) {
        this.userGoogleMfaCredentialsProvisioning = userGoogleMfaCredentialsProvisioning;
    }

    public void setMfaProviderProvisioning(MfaProviderProvisioning mfaProviderProvisioning) {
        this.mfaProviderProvisioning = mfaProviderProvisioning;
    }

    public void setGoogleAuthenticatorService(GoogleAuthenticatorAdapter googleAuthenticatorService) {
        this.googleAuthenticatorService = googleAuthenticatorService;
    }

    private UaaPrincipal getSessionAuthPrincipal(HttpSession session) {
        UaaAuthentication sessionAuth = session.getAttribute(MFA_VALIDATE_USER) instanceof UaaAuthentication ? (UaaAuthentication) session.getAttribute(MFA_VALIDATE_USER) : null;
        if(sessionAuth != null) {
            return sessionAuth.getPrincipal();
        } else {
            return null;
        }
    }
}
