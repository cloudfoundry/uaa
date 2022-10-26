package org.cloudfoundry.identity.uaa.invitations;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserDetails;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.SamlRedirectUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.ldap.AuthenticationException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.INVITATION;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.ORIGIN;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER;
import static org.cloudfoundry.identity.uaa.util.SessionUtils.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@Controller
@RequestMapping("/invitations")
public class InvitationsController {

    private static Logger logger = LoggerFactory.getLogger(InvitationsController.class);

    private final InvitationsService invitationsService;
    private final ExpiringCodeStore expiringCodeStore;
    private final PasswordValidator passwordValidator;
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager;
    private final UaaUserDatabase userDatabase;
    private final String spEntityID;
    private final ScimUserProvisioning userProvisioning;
    private final ExternalOAuthProviderConfigurator externalOAuthProviderConfigurator;

    public InvitationsController(
            final InvitationsService invitationsService,
            final ExpiringCodeStore expiringCodeStore,
            final PasswordValidator passwordValidator,
            final IdentityProviderProvisioning identityProviderProvisioning,
            final DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager,
            final UaaUserDatabase userDatabase,
            final @Qualifier("samlEntityID") String spEntityID,
            final ScimUserProvisioning userProvisioning,
            final @Qualifier("externalOAuthProviderConfigurator") ExternalOAuthProviderConfigurator externalOAuthProviderConfigurator) {
        this.invitationsService = invitationsService;
        this.expiringCodeStore = expiringCodeStore;
        this.passwordValidator = passwordValidator;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.zoneAwareAuthenticationManager = zoneAwareAuthenticationManager;
        this.userDatabase = userDatabase;
        this.spEntityID = spEntityID;
        this.userProvisioning = userProvisioning;
        this.externalOAuthProviderConfigurator = externalOAuthProviderConfigurator;
    }

    @RequestMapping(value = {"/sent", "/new", "/new.do"})
    public void return404(HttpServletResponse response) {
        response.setStatus(404);
    }

    @RequestMapping(value = "/accept", method = GET, params = {"code"})
    public String acceptInvitePage(@RequestParam String code, Model model, HttpServletRequest request, HttpServletResponse response) {

        ExpiringCode expiringCode = expiringCodeStore.peekCode(code, IdentityZoneHolder.get().getId());
        if ((null == expiringCode) || (null != expiringCode.getIntent() && !INVITATION.name().equals(expiringCode.getIntent()))) {
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_invite");
        }

        transferErrorParameters(model, request);

        Map<String, String> codeData = JsonUtils.readValue(expiringCode.getData(), new TypeReference<>() {
        });
        String origin = codeData.get(ORIGIN);
        try {
            IdentityProvider provider = identityProviderProvisioning.retrieveByOrigin(origin, IdentityZoneHolder.get().getId());

            UaaUser user = userDatabase.retrieveUserById(codeData.get("user_id"));
            boolean isUaaUserAndVerified =
                    UAA.equals(provider.getType()) && user.isVerified();
            boolean isExternalUserAndAcceptedInvite =
                    !UAA.equals(provider.getType()) && UaaHttpRequestUtils.isAcceptedInvitationAuthentication();
            if (isUaaUserAndVerified || isExternalUserAndAcceptedInvite) {
                AcceptedInvitation accepted = invitationsService.acceptInvitation(code, "");
                String redirect = "redirect:" + accepted.getRedirectUri();
                logger.debug(String.format("Redirecting accepted invitation for email:%s, id:%s to URL:%s", codeData.get("email"), codeData.get("user_id"), redirect));
                return redirect;
            } else if (SAML.equals(provider.getType())) {
                setRequestAttributes(request, code, user);

                SamlIdentityProviderDefinition definition = ObjectUtils.castInstance(provider.getConfig(), SamlIdentityProviderDefinition.class);

                String redirect = "redirect:/" + SamlRedirectUtils.getIdpRedirectUrl(definition, spEntityID, IdentityZoneHolder.get());
                logger.debug(String.format("Redirecting invitation for email:%s, id:%s single SAML IDP URL:%s", codeData.get("email"), codeData.get("user_id"), redirect));
                return redirect;
            } else if (OIDC10.equals(provider.getType()) || OAUTH20.equals(provider.getType())) {
                setRequestAttributes(request, code, user);

                AbstractExternalOAuthIdentityProviderDefinition definition = ObjectUtils.castInstance(provider.getConfig(), AbstractExternalOAuthIdentityProviderDefinition.class);

                String redirect = "redirect:" + externalOAuthProviderConfigurator.getIdpAuthenticationUrl(definition, provider.getOriginKey(), request);
                logger.debug(String.format("Redirecting invitation for email:%s, id:%s OIDC IDP URL:%s", codeData.get("email"), codeData.get("user_id"), redirect));
                return redirect;
            } else {
                UaaPrincipal uaaPrincipal = new UaaPrincipal(codeData.get("user_id"), codeData.get("email"), codeData.get("email"), origin, null, IdentityZoneHolder.get().getId());
                AnonymousAuthenticationToken token = new AnonymousAuthenticationToken("scim.invite", uaaPrincipal,
                        Collections.singletonList(UaaAuthority.UAA_INVITED));
                SecurityContextHolder.getContext().setAuthentication(token);
                model.addAttribute("provider", provider.getType());
                model.addAttribute("code", code);
                model.addAttribute("email", codeData.get("email"));
                logger.debug(String.format("Sending user to accept invitation page email:%s, id:%s", codeData.get("email"), codeData.get("user_id")));
            }
            updateModelWithConsentAttributes(model);
            return "invitations/accept_invite";
        } catch (EmptyResultDataAccessException noProviderFound) {
            logger.debug(String.format("No available invitation providers for email:%s, id:%s", codeData.get("email"), codeData.get("user_id")));
            return handleUnprocessableEntity(model, response, "error_message_code", "no_suitable_idp", "invitations/accept_invite");
        }
    }

    private void updateModelWithConsentAttributes(Model model) {
        BrandingInformation zoneBranding = IdentityZoneHolder.get().getConfig().getBranding();
        if (zoneBranding != null && zoneBranding.getConsent() != null) {
            model.addAttribute("consent_text", zoneBranding.getConsent().getText());
            model.addAttribute("consent_link", zoneBranding.getConsent().getLink());
        }
    }

    private void transferErrorParameters(Model model, HttpServletRequest request) {
        for (String p : Arrays.asList("error_message_code", "error_code", "error_message")) {
            if (hasText(request.getParameter(p))) {
                model.addAttribute(p, request.getParameter(p));
            }
        }
    }

    private void setRequestAttributes(HttpServletRequest request, String newCode, UaaUser user) {
        RequestContextHolder.getRequestAttributes().setAttribute("IS_INVITE_ACCEPTANCE", true, RequestAttributes.SCOPE_SESSION);
        RequestContextHolder.getRequestAttributes().setAttribute("user_id", user.getId(), RequestAttributes.SCOPE_SESSION);
        HttpServletRequestWrapper wrapper = getNewCodeWrapper(request, newCode);

        SavedRequest savedRequest = new DefaultSavedRequest(wrapper, new PortResolverImpl());
        RequestContextHolder.getRequestAttributes().setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest, RequestAttributes.SCOPE_SESSION);
    }

    private HttpServletRequestWrapper getNewCodeWrapper(final HttpServletRequest request, final String newCode) {
        return new HttpServletRequestWrapper(request) {
            @Override
            public String getParameter(String name) {
                if ("code".equals(name)) {
                    return newCode;
                }
                return super.getParameter(name);
            }

            @Override
            public Map<String, String[]> getParameterMap() {
                Map<String, String[]> result = super.getParameterMap();
                Map<String, String[]> modified = new HashMap<>(result);
                modified.remove("code");
                modified.put("code", new String[]{newCode});
                return modified;
            }

            @Override
            public Enumeration<String> getParameterNames() {
                return super.getParameterNames();
            }

            @Override
            public String[] getParameterValues(String name) {
                if ("code".equals(name)) {
                    return new String[]{newCode};
                }
                return super.getParameterValues(name);
            }

            @Override
            public String getQueryString() {
                return "code=" + newCode;
            }
        };
    }

    @RequestMapping(value = "/accept.do", method = POST)
    public String acceptInvitation(@RequestParam("password") String password,
                                   @RequestParam("password_confirmation") String passwordConfirmation,
                                   @RequestParam("code") String code,
                                   @RequestParam(value = "does_user_consent", required = false) boolean doesUserConsent,
                                   Model model,
                                   HttpServletResponse response) {

        PasswordConfirmationValidation validation = new PasswordConfirmationValidation(password, passwordConfirmation);

        UaaPrincipal principal = (UaaPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        final ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code, IdentityZoneHolder.get().getId());

        if (expiringCode == null || expiringCode.getData() == null) {
            logger.debug("Failing invitation. Code not found.");
            SecurityContextHolder.clearContext();
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_invite");
        }
        Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<>() {
        });
        if (principal == null || data.get("user_id") == null || !data.get("user_id").equals(principal.getId())) {
            logger.debug("Failing invitation. Code and user ID mismatch.");
            SecurityContextHolder.clearContext();
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_invite");
        }

        final String newCode = expiringCodeStore.generateCode(expiringCode.getData(), new Timestamp(System.currentTimeMillis() + (10 * 60 * 1000)), expiringCode.getIntent(), IdentityZoneHolder.get().getId()).getCode();
        BrandingInformation zoneBranding = IdentityZoneHolder.get().getConfig().getBranding();
        if (zoneBranding != null && zoneBranding.getConsent() != null && !doesUserConsent) {
            return processErrorReload(newCode, model, principal.getEmail(), response, "error_message_code", "missing_consent");
        }
        if (!validation.valid()) {
            return processErrorReload(newCode, model, principal.getEmail(), response, "error_message_code", validation.getMessageCode());
        }
        try {
            passwordValidator.validate(password);
        } catch (InvalidPasswordException e) {
            return processErrorReload(newCode, model, principal.getEmail(), response, "error_message", e.getMessagesAsOneString());
        }
        AcceptedInvitation invitation;
        try {
            invitation = invitationsService.acceptInvitation(newCode, password);
        } catch (HttpClientErrorException e) {
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_invite");
        }
        String res = "redirect:/login?success=invite_accepted";
        if (!invitation.getRedirectUri().equals("/home")) {
            res += "&" + FORM_REDIRECT_PARAMETER + "=" + invitation.getRedirectUri();
        }
        return res;
    }

    private String processErrorReload(String code, Model model, String email, HttpServletResponse response, String errorCode, String error) {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code, IdentityZoneHolder.get().getId());
        Map<String, String> codeData = JsonUtils.readValue(expiringCode.getData(), new TypeReference<>() {
        });
        try {
            String newCode = expiringCodeStore.generateCode(expiringCode.getData(), new Timestamp(System.currentTimeMillis() + (10 * 60 * 1000)), expiringCode.getIntent(), IdentityZoneHolder.get().getId()).getCode();

            model.addAttribute(errorCode, error);
            model.addAttribute("code", newCode);
            return "redirect:accept";
        } catch (EmptyResultDataAccessException noProviderFound) {
            logger.debug(String.format("No available invitation providers for email:%s, id:%s", codeData.get("email"), codeData.get("user_id")));
            return handleUnprocessableEntity(model, response, "error_message_code", "no_suitable_idp", "invitations/accept_invite");
        }
    }

    @RequestMapping(value = "/accept_enterprise.do", method = POST)
    public String acceptLdapInvitation(@RequestParam("enterprise_username") String username,
                                       @RequestParam("enterprise_password") String password,
                                       @RequestParam("enterprise_email") String email,
                                       @RequestParam("code") String code,
                                       Model model, HttpServletResponse response) {

        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code, IdentityZoneHolder.get().getId());
        if (expiringCode == null) {
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_enterprise.do");
        }

        String newCode = expiringCodeStore.generateCode(expiringCode.getData(), new Timestamp(System.currentTimeMillis() + (1000 * 60 * 10)), null, IdentityZoneHolder.get().getId()).getCode();

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        AuthenticationManager authenticationManager = null;
        IdentityProvider ldapProvider = null;
        try {
            ldapProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.LDAP, IdentityZoneHolder.get().getId());
            zoneAwareAuthenticationManager.getLdapAuthenticationManager(IdentityZoneHolder.get(), ldapProvider).getLdapAuthenticationManager();
            authenticationManager = zoneAwareAuthenticationManager.getLdapAuthenticationManager(IdentityZoneHolder.get(), ldapProvider).getLdapManagerActual();
        } catch (EmptyResultDataAccessException e) {
            //ldap provider was not available
            return handleUnprocessableEntity(model, response, "error_message_code", "no_suitable_idp", "invitations/accept_invite");
        } catch (Exception x) {
            logger.error("Unable to retrieve LDAP config.", x);
            return handleUnprocessableEntity(model, response, "error_message_code", "no_suitable_idp", "invitations/accept_invite");
        }
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(token);
            Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<>() {
            });
            ScimUser user = userProvisioning.retrieve(data.get("user_id"), IdentityZoneHolder.get().getId());
            if (!user.getPrimaryEmail().equalsIgnoreCase(((ExtendedLdapUserDetails) authentication.getPrincipal()).getEmailAddress())) {
                model.addAttribute("email", data.get("email"));
                model.addAttribute("provider", OriginKeys.LDAP);
                model.addAttribute("code", expiringCodeStore.generateCode(expiringCode.getData(), new Timestamp(System.currentTimeMillis() + (10 * 60 * 1000)), null, IdentityZoneHolder.get().getId()).getCode());
                return handleUnprocessableEntity(model, response, "error_message", "invite.email_mismatch", "invitations/accept_invite");
            }


            if (authentication.isAuthenticated()) {
                //change username from email to username
                user.setUserName(((ExtendedLdapUserDetails) authentication.getPrincipal()).getUsername());
                userProvisioning.update(user.getId(), user, IdentityZoneHolder.get().getId());
                zoneAwareAuthenticationManager.getLdapAuthenticationManager(IdentityZoneHolder.get(), ldapProvider).authenticate(token);
                AcceptedInvitation accept = invitationsService.acceptInvitation(newCode, "");
                return "redirect:" + "/login?success=invite_accepted&form_redirect_uri=" + URLEncoder.encode(accept.getRedirectUri());
            } else {
                return handleUnprocessableEntity(model, response, "error_message", "not authenticated", "invitations/accept_invite");
            }
        } catch (AuthenticationException x) {
            return handleUnprocessableEntity(model, response, "error_message", x.getMessage(), "invitations/accept_invite");
        } catch (Exception x) {
            logger.error("Unable to authenticate against LDAP", x);
            model.addAttribute("ldap", true);
            model.addAttribute("email", email);
            return handleUnprocessableEntity(model, response, "error_message", "bad_credentials", "invitations/accept_invite");
        }

    }

    private String handleUnprocessableEntity(Model model, HttpServletResponse response, String attributeKey, String attributeValue, String view) {
        model.addAttribute(attributeKey, attributeValue);
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        return view;
    }
}
