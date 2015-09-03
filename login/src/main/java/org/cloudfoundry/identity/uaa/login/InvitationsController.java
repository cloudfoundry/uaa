package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.ExpiringCodeService.CodeNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hibernate.validator.constraints.Email;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.util.Map;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;


@Controller
@RequestMapping("/invitations")
public class InvitationsController {
    private InvitationsService invitationsService;
    @Autowired @Qualifier("uaaPasswordValidator") private PasswordValidator passwordValidator;
    @Autowired private ExpiringCodeService expiringCodeService;

    public InvitationsController(InvitationsService invitationsService) {
        this.invitationsService = invitationsService;
    }

    @RequestMapping(value = "/new", method = GET)
    public String newInvitePage(Model model, @RequestParam(required = false, value = "client_id") String clientId,
                                @RequestParam(required = false, value = "redirect_uri") String redirectUri) {
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        return "invitations/new_invite";
    }


    @RequestMapping(value = "/new.do", method = POST, params = {"email"})
    public String sendInvitationEmail(@Valid @ModelAttribute("email") ValidEmail email, BindingResult result,
                                       @RequestParam(defaultValue = "", value = "client_id") String clientId,
                                      @RequestParam(defaultValue = "", value = "redirect_uri") String redirectUri,
                                      Model model, HttpServletResponse response) {
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
    public String acceptInvitePage(@RequestParam String code, Model model, HttpServletResponse response) throws IOException {
        try {
            Map<String, String> codeData = expiringCodeService.verifyCode(code);
            UaaPrincipal uaaPrincipal = new UaaPrincipal(codeData.get("user_id"), codeData.get("email"), codeData.get("email"), Origin.UAA, null, IdentityZoneHolder.get().getId());
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
            SecurityContextHolder.getContext().setAuthentication(token);
            model.addAllAttributes(codeData);
            return "invitations/accept_invite";
        } catch (CodeNotFoundException e) {
            return handleUnprocessableEntity(model, response, "error_message_code", "code_expired", "invitations/accept_invite");
        }
    }

    @RequestMapping(value = "/accept.do", method = POST)
    public String acceptInvitation(@RequestParam("password") String password,
                                   @RequestParam("password_confirmation") String passwordConfirmation,
                                   @RequestParam(defaultValue = "", value = "client_id") String clientId,
                                   @RequestParam(defaultValue = "", value = "redirect_uri") String redirectUri,
                                   Model model, HttpServletResponse servletResponse) throws IOException {

        PasswordConfirmationValidation validation = new PasswordConfirmationValidation(password, passwordConfirmation);

        UaaPrincipal principal =  (UaaPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (!validation.valid()) {
            model.addAttribute("email", principal.getEmail());
            return handleUnprocessableEntity(model, servletResponse, "error_message_code", validation.getMessageCode(), "invitations/accept_invite");
        }
        try {
            passwordValidator.validate(password);
        } catch (InvalidPasswordException e) {
            model.addAttribute("email", principal.getEmail());
            return handleUnprocessableEntity(model, servletResponse, "error_message", e.getMessagesAsOneString(), "invitations/accept_invite");
        }

        String redirectLocation = invitationsService.acceptInvitation(principal.getId(), principal.getEmail(), password, clientId, redirectUri);
        return "redirect:" + redirectLocation;
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
