package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.ExpiringCodeService.CodeNotFoundException;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.SamlRedirectUtils;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.hibernate.validator.constraints.Email;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;


@Controller
@RequestMapping("/invitations")
public class InvitationsController {

    private static Log logger = LogFactory.getLog(InvitationsController.class);

    private final InvitationsService invitationsService;
    @Autowired @Qualifier("uaaPasswordValidator") private PasswordValidator passwordValidator;
    @Autowired private ExpiringCodeService expiringCodeService;
    @Autowired private IdentityProviderProvisioning providerProvisioning;
    @Autowired private ClientDetailsService clientDetailsService;
    @Autowired private DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager;

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

    protected List<String> getProvidersForClient(String clientId) {
        if (clientId==null) {
            return null;
        } else {
            try {
                ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
                return (List<String>) client.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS);
            } catch (NoSuchClientException x) {
                return null;
            }
        }
    }

    protected List<String> getEmailDomain(IdentityProvider provider) {
        AbstractIdentityProviderDefinition definition = null;
        if (provider.getConfig()!=null) {
            switch (provider.getType()) {
                case Origin.UAA: {
                    definition = provider.getConfigValue(UaaIdentityProviderDefinition.class);
                    break;
                }
                case Origin.LDAP: {
                    try {
                        definition = provider.getConfigValue(LdapIdentityProviderDefinition.class);
                    } catch (JsonUtils.JsonUtilException x) {
                        logger.error("Unable to parse LDAP configuration:"+provider.getConfig());
                    }
                    break;
                }
                case Origin.SAML: {
                    definition = provider.getConfigValue(SamlIdentityProviderDefinition.class);
                    break;
                }
                default: {
                    break;
                }
            }
        }
        if (definition!=null) {
            return definition.getEmailDomain();
        }
        return null;
    }

    protected boolean doesEmailDomainMatchProvider(IdentityProvider provider, String domain) {
        List<String> domainList = getEmailDomain(provider);
        return domainList == null ? true : domainList.contains(domain);
    }

    protected List<IdentityProvider> filterIdpsForClientAndEmailDomain(String clientId, String email) {
        List<IdentityProvider> providers = providerProvisioning.retrieveActive(IdentityZoneHolder.get().getId());
        if (providers!=null && providers.size()>0) {
            //filter client providers
            List<String> clientFilter = getProvidersForClient(clientId);
            if (clientFilter!=null && clientFilter.size()>0) {
                providers =
                    providers.stream().filter(
                        p -> clientFilter.contains(p.getId())
                    ).collect(Collectors.toList());
            }
            //filter for email domain
            if (email!=null && email.contains("@")) {
                final String domain = email.substring(email.indexOf('@') + 1);
                providers =
                    providers.stream().filter(
                        p -> doesEmailDomainMatchProvider(p, domain)
                    ).collect(Collectors.toList());
            }
        }
        return providers;
    }

    @RequestMapping(value = "/new", method = GET)
    public String newInvitePage(Model model,
                                @RequestParam(required = false, value = "client_id") String clientId,
                                @RequestParam(required = false, value = "redirect_uri") String redirectUri) {
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        return "invitations/new_invite";
    }


    @RequestMapping(value = "/new.do", method = POST, params = {"email"})
    public String sendInvitationEmail(@Valid @ModelAttribute("email") ValidEmail email, BindingResult result,
                                       @RequestParam(defaultValue = "", value = "client_id") String clientId,
                                      @RequestParam(defaultValue = "", value = "redirect_uri") String redirectUri,
                                      Model model,
                                      HttpServletResponse response) {
        if (result.hasErrors()) {
            return handleUnprocessableEntity(model, response, "error_message_code", "invalid_email", "invitations/new_invite");
        }

        UaaPrincipal p = ((UaaPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        String currentUser = p.getName();
        try {
           invitationsService.inviteUser(email.getEmail(), currentUser, clientId, redirectUri);
        } catch (UaaException e) {
           return handleUnprocessableEntity(model, response, "error_message_code", "existing_user", "invitations/new_invite");
        }
        return "redirect:sent";
    }

    @RequestMapping(value = "sent", method = GET)
    public String inviteSentPage() {
        return "invitations/invite_sent";
    }

    @RequestMapping(value = "/accept", method = GET, params = {"code"})
    public String acceptInvitePage(@RequestParam String code, Model model, HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            Map<String, String> codeData = expiringCodeService.verifyCode(code);
            List<IdentityProvider> providers = filterIdpsForClientAndEmailDomain(codeData.get("client_id"), codeData.get("email"));
            if (providers!=null && providers.size()==0) {
                logger.debug(String.format("No available invitation providers for email:%s, id:%s", codeData.get("email"), codeData.get("user_id")));
                return handleUnprocessableEntity(model, response, "error_message_code", "no_suitable_idp", "invitations/accept_invite");
            } else {
                UaaPrincipal uaaPrincipal = new UaaPrincipal(codeData.get("user_id"), codeData.get("email"), codeData.get("email"), Origin.UNKNOWN, null, IdentityZoneHolder.get().getId());
                UaaAuthentication token = new UaaAuthentication(uaaPrincipal, UaaAuthority.USER_AUTHORITIES, new UaaAuthenticationDetails(request));
                SecurityContextHolder.getContext().setAuthentication(token);
                if (providers != null && providers.size() == 1 && Origin.SAML.equals(providers.get(0).getType())) {
                    SamlIdentityProviderDefinition definition = providers.get(0).getConfigValue(SamlIdentityProviderDefinition.class);
                    String redirect = "redirect:/" + SamlRedirectUtils.getIdpRedirectUrl(definition, getSpEntityID());
                    logger.debug(String.format("Redirecting invitation for email:%s, id:%s single SAML IDP URL:%s", codeData.get("email"), codeData.get("user_id"), redirect));
                    return redirect;
                } else {
                    getProvidersByType(model, providers, Origin.UAA);
                    getProvidersByType(model, providers, Origin.SAML);
                    getProvidersByType(model, providers, Origin.LDAP);
                    model.addAttribute("entityID", SamlRedirectUtils.getZonifiedEntityId(getSpEntityID()));
                    logger.debug(String.format("Sending user to accept invitation page email:%s, id:%s", codeData.get("email"), codeData.get("user_id")));
                }
            }
            model.addAllAttributes(codeData);
            return "invitations/accept_invite";
        } catch (CodeNotFoundException e) {
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_invite");
        }
    }

    protected void getProvidersByType(Model model, List<IdentityProvider> providers, String type) {
        List<IdentityProvider> result = providers.stream().filter(p -> type.equals(p.getType())).collect(Collectors.toList());
        if (!result.isEmpty()) {
            if (Origin.SAML.equals(result.get(0).getType())) {
                List<SamlIdentityProviderDefinition> idps = new LinkedList<>();
                for (IdentityProvider p : result) {
                    idps.add(p.getConfigValue(SamlIdentityProviderDefinition.class));
                }
                model.addAttribute("idps", idps);
            }
            model.addAttribute(type, result);
        }
    }

    @RequestMapping(value = "/accept_enterprise.do", method = POST)
    public String acceptLdapInvitation(@RequestParam("enterprise_username") String username,
                                       @RequestParam("enterprise_password") String password,
                                       @RequestParam(value = "client_id", required = false, defaultValue = "") String clientId,
                                       @RequestParam(value = "redirect_uri", required = false, defaultValue = "") String redirectUri,
                                       Model model, HttpServletResponse response) throws IOException {

        UaaPrincipal principal =  null;
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        AuthenticationManager authenticationManager = null;
        try {
            IdentityProvider ldapProvider = providerProvisioning.retrieveByOrigin(Origin.LDAP, IdentityZoneHolder.get().getId());
            authenticationManager = zoneAwareAuthenticationManager.getLdapAuthenticationManager(IdentityZoneHolder.get(), ldapProvider);
        } catch (EmptyResultDataAccessException e) {
            //ldap provider was not available
            return handleUnprocessableEntity(model, response, "error_message_code", "no_suitable_idp", "invitations/accept_invite");
        } catch (Exception x) {
            logger.error("Unable to retrieve LDAP config.", x);
            return handleUnprocessableEntity(model, response, "error_message_code", "no_suitable_idp", "invitations/accept_invite");
        }
        Authentication authentication = null;
        try {
            authentication = authenticationManager.authenticate(token);
            principal = (UaaPrincipal) authentication.getPrincipal();
        } catch (AuthenticationException x) {
             return handleUnprocessableEntity(model, response, "error_message", x.getMessage(), "invitations/accept_invite");
        } catch (Exception x) {
            logger.error("Unable to authenticate against LDAP", x);
            return handleUnprocessableEntity(model, response, "error_message", x.getMessage(), "invitations/accept_invite");
        }

        String redirectLocation = invitationsService.acceptInvitation(principal.getId(), principal.getEmail(), password, clientId, redirectUri, Origin.LDAP).getRedirectUri();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        if (StringUtils.hasText(redirectUri)) {
            return "redirect:" + redirectUri;
        }
        if (redirectLocation != null) {
            return "redirect:" + redirectLocation;
        }
        return "redirect:/home";
    }

    @RequestMapping(value = "/accept.do", method = POST)
    public String acceptInvitation(@RequestParam("password") String password,
                                   @RequestParam("password_confirmation") String passwordConfirmation,
                                   @RequestParam(value = "client_id", required = false, defaultValue = "") String clientId,
                                   @RequestParam(value = "redirect_uri", required = false, defaultValue = "") String redirectUri,
                                   Model model,
                                   HttpServletRequest request,
                                   HttpServletResponse response) throws IOException {

        PasswordConfirmationValidation validation = new PasswordConfirmationValidation(password, passwordConfirmation);

        UaaPrincipal principal =  (UaaPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (!validation.valid()) {
            model.addAttribute("email", principal.getEmail());
            return handleUnprocessableEntity(model, response, "error_message_code", validation.getMessageCode(), "invitations/accept_invite");
        }
        try {
            passwordValidator.validate(password);
        } catch (InvalidPasswordException e) {
            model.addAttribute("email", principal.getEmail());
            return handleUnprocessableEntity(model, response, "error_message", e.getMessagesAsOneString(), "invitations/accept_invite");
        }
        InvitationsService.AcceptedInvitation invitation = invitationsService.acceptInvitation(principal.getId(), principal.getEmail(), password, clientId, redirectUri, Origin.UAA);
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

    private String handleUnprocessableEntity(Model model, HttpServletResponse response, String attributeKey, String attributeValue, String view) {
        model.addAttribute(attributeKey, attributeValue);
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        return view;
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
