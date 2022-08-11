package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.util.DomainFilter;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import javax.validation.constraints.Email;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@Controller
public class AccountsController {

    private final AccountCreationService accountCreationService;
    private final IdentityProviderProvisioning identityProviderProvisioning;

    public AccountsController(
            final AccountCreationService accountCreationService,
            final IdentityProviderProvisioning identityProviderProvisioning) {
        this.accountCreationService = accountCreationService;
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    @RequestMapping(value = "/create_account", method = GET)
    public String activationEmail(Model model,
                                  @RequestParam(value = "client_id", required = false) String clientId,
                                  @RequestParam(value = "redirect_uri", required = false) String redirectUri,
                                  HttpServletResponse response) {
        if (!IdentityZoneHolder.get().getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled()) {
            return handleSelfServiceDisabled(model, response, "error_message_code", "self_service_disabled");
        }
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        updateModelWithConsentAttributes(model);

        return "accounts/new_activation_email";
    }

    @RequestMapping(value = "/create_account.do", method = POST)
    public String sendActivationEmail(Model model, HttpServletResponse response,
                                      @RequestParam(value = "client_id", required = false) String clientId,
                                      @RequestParam(value = "redirect_uri", required = false) String redirectUri,
                                      @Valid @ModelAttribute("email") ValidEmail email, BindingResult result,
                                      @RequestParam("password") String password,
                                      @RequestParam("password_confirmation") String passwordConfirmation,
                                      @RequestParam(value = "does_user_consent", required = false) boolean doesUserConsent) {

        BrandingInformation zoneBranding = IdentityZoneHolder.get().getConfig().getBranding();
        if (zoneBranding != null && zoneBranding.getConsent() != null && !doesUserConsent) {
            return handleUnprocessableEntity(model, response, "error_message_code", "missing_consent");
        }
        if (!IdentityZoneHolder.get().getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled()) {
            return handleSelfServiceDisabled(model, response, "error_message_code", "self_service_disabled");
        }
        if (result.hasErrors()) {
            return handleUnprocessableEntity(model, response, "error_message_code", "invalid_email");
        }

        List<IdentityProvider> identityProviderList = DomainFilter.getIdpsForEmailDomain(identityProviderProvisioning.retrieveAll(true, IdentityZoneHolder.get().getId()), email.getEmail());
        identityProviderList = identityProviderList.stream().filter(idp -> !idp.getOriginKey().equals(OriginKeys.UAA)).collect(Collectors.toList());
        if (!identityProviderList.isEmpty()) {
            model.addAttribute("email", email.getEmail());
            return handleUnprocessableEntity(model, response, "error_message_code", "other_idp");
        }
        PasswordConfirmationValidation validation = new PasswordConfirmationValidation(password, passwordConfirmation);
        if (!validation.valid()) {
            return handleUnprocessableEntity(model, response, "error_message_code", validation.getMessageCode());
        }
        try {
            accountCreationService.beginActivation(email.getEmail(), password, clientId, redirectUri);
        } catch (UaaException e) {
            return handleUnprocessableEntity(model, response, "error_message_code", "username_exists");
        } catch (InvalidPasswordException e) {
            return handleUnprocessableEntity(model, response, "error_message", e.getMessagesAsOneString());
        }
        return "redirect:accounts/email_sent";
    }

    @RequestMapping(value = "/accounts/email_sent", method = RequestMethod.GET)
    public String emailSent() {
        return "accounts/email_sent";
    }

    @RequestMapping(value = "/verify_user", method = GET)
    public String verifyUser(Model model,
                             @RequestParam("code") String code,
                             HttpServletResponse response, HttpSession session) {

        AccountCreationService.AccountCreationResponse accountCreation;
        try {
            accountCreation = accountCreationService.completeActivation(code);
        } catch (HttpClientErrorException e) {
            model.addAttribute("error_message_code", "code_expired");
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return "accounts/link_prompt";
        }

        String redirectLocation = accountCreation.getRedirectLocation();
        String res = "redirect:/login?success=verify_success";
        if (!redirectLocation.equals(accountCreationService.getDefaultRedirect())) {
            res += "&form_redirect_uri=" + redirectLocation;
        }
        return res;
    }

    private String handleUnprocessableEntity(Model model, HttpServletResponse response, String attributeKey, String attributeValue) {
        model.addAttribute(attributeKey, attributeValue);
        updateModelWithConsentAttributes(model);
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        return "accounts/new_activation_email";
    }

    private String handleSelfServiceDisabled(Model model, HttpServletResponse response, String attributeKey, String attributeValue) {
        model.addAttribute(attributeKey, attributeValue);
        updateModelWithConsentAttributes(model);
        response.setStatus(HttpStatus.NOT_FOUND.value());
        return "error";
    }

    private void updateModelWithConsentAttributes(Model model) {
        BrandingInformation zoneBranding = IdentityZoneHolder.get().getConfig().getBranding();
        if (zoneBranding != null && zoneBranding.getConsent() != null) {
            model.addAttribute("consent_text", zoneBranding.getConsent().getText());
            model.addAttribute("consent_link", zoneBranding.getConsent().getLink());
        }
    }

    public static class ValidEmail {
        @Email
        String email;

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }
    }
}
