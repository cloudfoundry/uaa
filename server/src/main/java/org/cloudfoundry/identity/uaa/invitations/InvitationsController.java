package org.cloudfoundry.identity.uaa.invitations;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.invitations.InvitationsService.AcceptedInvitation;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserDetails;
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
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
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
import java.io.IOException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.INVITATION;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.ORIGIN;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;


@Controller
@RequestMapping("/invitations")
public class InvitationsController {

    private static Log logger = LogFactory.getLog(InvitationsController.class);

    private final InvitationsService invitationsService;

    private PasswordValidator passwordValidator;
    private ExpiringCodeStore expiringCodeStore;
    private IdentityProviderProvisioning providerProvisioning;
    private UaaUserDatabase userDatabase;
    private DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager;
    private ScimUserProvisioning userProvisioning;



    public void setExpiringCodeStore(ExpiringCodeStore expiringCodeStore) {
        this.expiringCodeStore = expiringCodeStore;
    }

    public void setPasswordValidator(PasswordValidator passwordValidator) {
        this.passwordValidator = passwordValidator;
    }

    public void setProviderProvisioning(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }
    public void setZoneAwareAuthenticationManager(DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager) {
        this.zoneAwareAuthenticationManager = zoneAwareAuthenticationManager;
    }

    public void setUserDatabase(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    private String spEntityID;

    public InvitationsController(InvitationsService invitationsService) {
        this.invitationsService = invitationsService;
    }

    public String getSpEntityID() {
        return spEntityID;
    }

    public void setSpEntityID(String spEntityID) {
        this.spEntityID = spEntityID;
    }

    @RequestMapping(value = {"/sent", "/new", "/new.do"})
    public void return404(HttpServletResponse response) {
        response.setStatus(404);
    }

    @RequestMapping(value = "/accept", method = GET, params = {"code"})
    public String acceptInvitePage(@RequestParam String code, Model model, HttpServletRequest request, HttpServletResponse response) throws IOException {

        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code);
        if ((null == expiringCode) || (null != expiringCode.getIntent() && !INVITATION.name().equals(expiringCode.getIntent()))) {
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_invite");
        }

        transferErrorParameters(model, request);

        Map<String, String> codeData = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
        String origin = codeData.get(ORIGIN);
        try {
            IdentityProvider provider = providerProvisioning.retrieveByOrigin(origin, IdentityZoneHolder.get().getId());
            final String newCode = expiringCodeStore.generateCode(expiringCode.getData(), new Timestamp(System.currentTimeMillis() + (10 * 60 * 1000)), expiringCode.getIntent()).getCode();

            UaaUser user = userDatabase.retrieveUserById(codeData.get("user_id"));
            if (user.isVerified()) {
                AcceptedInvitation accepted = invitationsService.acceptInvitation(newCode, "");
                String redirect = "redirect:" + accepted.getRedirectUri();
                logger.debug(String.format("Redirecting accepted invitation for email:%s, id:%s to URL:%s", codeData.get("email"), codeData.get("user_id"), redirect));
                return redirect;
            } else if (SAML.equals(provider.getType())) {
                setRequestAttributes(request, newCode, user);

                SamlIdentityProviderDefinition definition = ObjectUtils.castInstance(provider.getConfig(), SamlIdentityProviderDefinition.class);

                String redirect = "redirect:/" + SamlRedirectUtils.getIdpRedirectUrl(definition, getSpEntityID());
                logger.debug(String.format("Redirecting invitation for email:%s, id:%s single SAML IDP URL:%s", codeData.get("email"), codeData.get("user_id"), redirect));
                return redirect;
            } else if (OIDC10.equals(provider.getType()) || OAUTH20.equals(provider.getType())) {
                setRequestAttributes(request, newCode, user);

                AbstractXOAuthIdentityProviderDefinition definition = ObjectUtils.castInstance(provider.getConfig(), AbstractXOAuthIdentityProviderDefinition.class);

                String scheme = request.getScheme();
                String host = request.getHeader("Host");
                String contextPath = request.getContextPath();
                String resultPath = scheme + "://" + host + contextPath;
                String redirect = "redirect:" + definition.getAuthUrl() + "?client_id=" + definition.getRelyingPartyId() + "&response_type=code" + "&redirect_uri=" + resultPath + "/login/callback/" + provider.getOriginKey();

                logger.debug(String.format("Redirecting invitation for email:%s, id:%s OIDC IDP URL:%s", codeData.get("email"), codeData.get("user_id"), redirect));
                return redirect;
            } else {
                UaaPrincipal uaaPrincipal = new UaaPrincipal(codeData.get("user_id"), codeData.get("email"), codeData.get("email"), origin, null, IdentityZoneHolder.get().getId());
                AnonymousAuthenticationToken token = new AnonymousAuthenticationToken("scim.invite",uaaPrincipal, Arrays.asList(UaaAuthority.UAA_INVITED));
                SecurityContextHolder.getContext().setAuthentication(token);
                model.addAttribute("provider", provider.getType());
                model.addAttribute("code", newCode);
                model.addAttribute("email", codeData.get("email"));
                logger.debug(String.format("Sending user to accept invitation page email:%s, id:%s", codeData.get("email"), codeData.get("user_id")));
            }
            return "invitations/accept_invite";
        } catch (EmptyResultDataAccessException noProviderFound) {
            logger.debug(String.format("No available invitation providers for email:%s, id:%s", codeData.get("email"), codeData.get("user_id")));
            return handleUnprocessableEntity(model, response, "error_message_code", "no_suitable_idp", "invitations/accept_invite");
        }
    }

    public void transferErrorParameters(Model model, HttpServletRequest request) {
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

    protected HttpServletRequestWrapper getNewCodeWrapper(final HttpServletRequest request, final String newCode) {
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
                return "code="+newCode;
            }
        };
    }

    @RequestMapping(value = "/accept.do", method = POST)
    public String acceptInvitation(@RequestParam("password") String password,
                                   @RequestParam("password_confirmation") String passwordConfirmation,
                                   @RequestParam("code") String code,
                                   Model model,
                                   HttpServletRequest request,
                                   HttpServletResponse response) throws IOException {

        PasswordConfirmationValidation validation = new PasswordConfirmationValidation(password, passwordConfirmation);

        UaaPrincipal principal =  (UaaPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        final ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code);

        if (expiringCode == null || expiringCode.getData() == null) {
            logger.debug("Failing invitation. Code not found.");
            SecurityContextHolder.clearContext();
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_invite");
        }
        Map<String,String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String,String>>() {});
        if (principal == null || data.get("user_id") == null || !data.get("user_id").equals(principal.getId())) {
            logger.debug("Failing invitation. Code and user ID mismatch.");
            SecurityContextHolder.clearContext();
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_invite");
        }

        final String newCode = expiringCodeStore.generateCode(expiringCode.getData(), new Timestamp(System.currentTimeMillis() + (10 * 60 * 1000)), expiringCode.getIntent()).getCode();
        if (!validation.valid()) {
           return processErrorReload(newCode, model, principal.getEmail(), response, "error_message_code", validation.getMessageCode());
//           return handleUnprocessableEntity(model, response, "error_message_code", validation.getMessageCode(), "invitations/accept_invite");
        }
        try {
            passwordValidator.validate(password);
        } catch (InvalidPasswordException e) {
            return processErrorReload(newCode, model, principal.getEmail(), response, "error_message", e.getMessagesAsOneString());
//            return handleUnprocessableEntity(model, response, "error_message", e.getMessagesAsOneString(), "invitations/accept_invite");
        }
        AcceptedInvitation invitation;
        try {
            invitation = invitationsService.acceptInvitation(newCode, password);
        } catch (HttpClientErrorException e) {
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_invite");
        }
        principal = new UaaPrincipal(
            invitation.getUser().getId(),
            invitation.getUser().getUserName(),
            invitation.getUser().getPrimaryEmail(),
            invitation.getUser().getOrigin(),
            invitation.getUser().getExternalId(),
            IdentityZoneHolder.get().getId()
        );
        UaaAuthentication authentication = new UaaAuthentication(principal, UaaAuthority.USER_AUTHORITIES, new UaaAuthenticationDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return "redirect:" + invitation.getRedirectUri();
    }

    private String processErrorReload(String code, Model model, String email, HttpServletResponse response, String errorCode, String error) {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code);
        Map<String, String> codeData = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
        try {
            String origin = codeData.get(ORIGIN);
            IdentityProvider provider = providerProvisioning.retrieveByOrigin(origin, IdentityZoneHolder.get().getId());
            String newCode = expiringCodeStore.generateCode(expiringCode.getData(), new Timestamp(System.currentTimeMillis() + (10 * 60 * 1000)), expiringCode.getIntent()).getCode();

            model.addAttribute(errorCode, error);
            model.addAttribute("code", newCode);
            return "redirect:accept";
            //return handleUnprocessableEntity(model, response, errorCode, error, "invitations/accept_invite");
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
                                       Model model, HttpServletResponse response) throws IOException {

        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code);
        if (expiringCode==null) {
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_enterprise.do");
        }

        String newCode = expiringCodeStore.generateCode(expiringCode.getData(), new Timestamp(System.currentTimeMillis() + (1000*60*10)), null).getCode();

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        AuthenticationManager authenticationManager = null;
        IdentityProvider ldapProvider = null;
        try {
            ldapProvider = providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, IdentityZoneHolder.get().getId());
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
            Map<String,String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String,String>>() {});
            ScimUser user = userProvisioning.retrieve(data.get("user_id"));
            if (!user.getPrimaryEmail().equalsIgnoreCase(((ExtendedLdapUserDetails) authentication.getPrincipal()).getEmailAddress())) {
                model.addAttribute("email", data.get("email"));
                model.addAttribute("provider", OriginKeys.LDAP);
                model.addAttribute("code", expiringCodeStore.generateCode(expiringCode.getData(), new Timestamp(System.currentTimeMillis() + (10 * 60 * 1000)), null).getCode());
                return handleUnprocessableEntity(model, response, "error_message", "invite.email_mismatch", "invitations/accept_invite");
            }


            if (authentication.isAuthenticated()) {
                //change username from email to username
                user.setUserName(((ExtendedLdapUserDetails) authentication.getPrincipal()).getUsername());
                userProvisioning.update(user.getId(), user);
                SecurityContextHolder.getContext().setAuthentication(zoneAwareAuthenticationManager.getLdapAuthenticationManager(IdentityZoneHolder.get(), ldapProvider).authenticate(token));
                AcceptedInvitation accept = invitationsService.acceptInvitation(newCode,"");
                return "redirect:" + accept.getRedirectUri();
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

    public void setUserProvisioning(ScimUserProvisioning userProvisioning) {
        this.userProvisioning = userProvisioning;
    }
}
