package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChange;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.MergedZoneBrandingInformation;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.sql.Timestamp;
import java.util.Map;

import static org.springframework.util.StringUtils.hasText;

@Controller
public class ResetPasswordController {
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private final IdentityZoneManager identityZoneManager;
    private final ResetPasswordService resetPasswordService;
    private final MessageService messageService;
    private final TemplateEngine templateEngine;
    private final ExpiringCodeStore codeStore;
    private final UaaUserDatabase userDatabase;

    private final String externalLoginUrl;

    public ResetPasswordController(
            final IdentityZoneManager identityZoneManager,
            final ResetPasswordService resetPasswordService,
            final MessageService messageService,
            final @Qualifier("mailTemplateEngine") TemplateEngine templateEngine,
            final ExpiringCodeStore codeStore,
            final UaaUserDatabase userDatabase,
            final @Value("${login.url}") String externalLoginUrl
    ) {
        this.identityZoneManager = identityZoneManager;
        this.resetPasswordService = resetPasswordService;
        this.messageService = messageService;
        this.templateEngine = templateEngine;
        this.codeStore = codeStore;
        this.userDatabase = userDatabase;
        this.externalLoginUrl = externalLoginUrl;
    }

    @GetMapping("/forgot_password")
    public String forgotPasswordPage(Model model,
            @RequestParam(required = false, value = "client_id") String clientId,
            @RequestParam(required = false, value = "redirect_uri") String redirectUri,
            HttpServletResponse response) {
        if (!identityZoneManager.getCurrentIdentityZone().getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled()) {
            return handleSelfServiceDisabled(model, response, "error_message_code", "self_service_disabled");
        }
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        return "forgot_password";
    }

    @PostMapping("/forgot_password.do")
    public String forgotPassword(Model model, @RequestParam("username") String username, @RequestParam(value = "client_id", defaultValue = "") String clientId,
            @RequestParam(value = "redirect_uri", defaultValue = "") String redirectUri, HttpServletResponse response) {
        if (!identityZoneManager.getCurrentIdentityZone().getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled()) {
            return handleSelfServiceDisabled(model, response, "error_message_code", "self_service_disabled");
        }
        forgotPassword(username, clientId, redirectUri);
        return "redirect:email_sent?code=reset_password";
    }

    private void forgotPassword(String username, String clientId, String redirectUri) {
        String subject = getSubjectText();
        String htmlContent = null;
        String userId = null;
        String email = null;

        try {
            ForgotPasswordInfo forgotPasswordInfo = resetPasswordService.forgotPassword(username, clientId, redirectUri);
            userId = forgotPasswordInfo.getUserId();
            email = forgotPasswordInfo.getEmail();
            htmlContent = getCodeSentEmailHtml(forgotPasswordInfo.getResetPasswordCode().getCode());
        } catch (ConflictException e) {
            email = e.getEmail();
            htmlContent = getResetUnavailableEmailHtml(email);
            userId = e.getUserId();
        } catch (NotFoundException e) {
            logger.error("User with email address {} not found.", username);
        }

        if (htmlContent != null && userId != null) {
            messageService.sendMessage(email, MessageType.PASSWORD_RESET, subject, htmlContent);
        }
    }

    private String getSubjectText() {
        String serviceName = getServiceName();
        if (UaaStringUtils.isEmpty(serviceName)) {
            return "Account password reset request";
        }
        return serviceName + " account password reset request";
    }

    private String getCodeSentEmailHtml(String code) {
        String resetUrl;
        if (UaaUrlUtils.isUrl(externalLoginUrl)) {
            resetUrl = UaaUrlUtils.getUaaUrl(UriComponentsBuilder.fromUriString(externalLoginUrl).path("/reset_password"), true, identityZoneManager.getCurrentIdentityZone());
        } else {
            resetUrl = UaaUrlUtils.getUaaUrl("/reset_password", identityZoneManager.getCurrentIdentityZone());
        }

        final Context ctx = new Context();
        ctx.setVariable("serviceName", getServiceName());
        ctx.setVariable("code", code);
        ctx.setVariable("resetUrl", resetUrl);
        return templateEngine.process("reset_password", ctx);
    }

    private String getResetUnavailableEmailHtml(String email) {
        String hostname = UaaUrlUtils.getUaaHost(identityZoneManager.getCurrentIdentityZone());

        final Context ctx = new Context();
        ctx.setVariable("serviceName", getServiceName());
        ctx.setVariable("email", email);
        ctx.setVariable("hostname", hostname);
        return templateEngine.process("reset_password_unavailable", ctx);
    }

    private String getServiceName() {
        if (identityZoneManager.isCurrentZoneUaa()) {
            String companyName = MergedZoneBrandingInformation.resolveBranding().getCompanyName();
            return StringUtils.hasText(companyName) ? companyName : "Cloud Foundry";
        } else {
            return identityZoneManager.getCurrentIdentityZone().getName();
        }
    }

    @GetMapping("/email_sent")
    public String emailSentPage(@ModelAttribute("code") String code,
            HttpServletResponse response) {
        response.addHeader("Content-Security-Policy", "frame-ancestors 'none'");
        return "email_sent";
    }

    @RequestMapping(value = "/reset_password", method = RequestMethod.HEAD)
    public void resetPassword() {
        // Some mail providers initially send a HEAD request to check the validity of the link before redirecting users.
    }

    @GetMapping(value = "/reset_password", params = {"code"})
    public String resetPasswordPage(Model model,
            HttpServletResponse response,
            @RequestParam("code") String code) {

        ExpiringCode expiringCode = checkIfUserExists(codeStore.retrieveCode(code, identityZoneManager.getCurrentIdentityZone().getId()));
        if (expiringCode == null) {
            return handleUnprocessableEntity(model, response, "message_code", "bad_code");
        } else {
            PasswordChange passwordChange = JsonUtils.readValue(expiringCode.getData(), PasswordChange.class);
            String userId = passwordChange.getUserId();
            UaaUser uaaUser = userDatabase.retrieveUserById(userId);
            String newCode = codeStore.generateCode(expiringCode.getData(), new Timestamp(System.currentTimeMillis() + (10 * 60 * 1000)), expiringCode.getIntent(), identityZoneManager.getCurrentIdentityZoneId()).getCode();
            model.addAttribute("code", newCode);
            model.addAttribute("email", uaaUser.getEmail());
            model.addAttribute("username", uaaUser.getUsername());
            return "reset_password";
        }
    }

    private ExpiringCode checkIfUserExists(ExpiringCode code) {
        if (code == null) {
            logger.debug("reset_password ExpiringCode object is null. Aborting.");
            return null;
        }
        if (!hasText(code.getData())) {
            logger.debug("reset_password ExpiringCode[{}] data string is null or empty. Aborting.", code.getCode());
            return null;
        }
        Map<String, String> data = JsonUtils.readValue(code.getData(), new TypeReference<Map<String, String>>() {
        });
        if (!hasText(data.get("user_id"))) {
            logger.debug("reset_password ExpiringCode[{}] user_id string is null or empty. Aborting.", code.getCode());
            return null;
        }
        String userId = data.get("user_id");
        try {
            userDatabase.retrieveUserById(userId);
        } catch (UsernameNotFoundException e) {
            logger.debug("reset_password ExpiringCode[{}] user_id is invalid. Aborting.", code.getCode());
            return null;
        }
        return code;
    }

    @PostMapping("/reset_password.do")
    public void resetPassword(Model model,
            @RequestParam("code") String code,
            @RequestParam("email") String email,
            @RequestParam("password") String password,
            @RequestParam("password_confirmation") String passwordConfirmation,
            HttpServletRequest request,
            HttpServletResponse response,
            HttpSession session) {


    }

    private String handleUnprocessableEntity(Model model, HttpServletResponse response, String attributeKey, String attributeValue) {
        model.addAttribute(attributeKey, attributeValue);
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        return "forgot_password";
    }

    private String handleSelfServiceDisabled(Model model, HttpServletResponse response, String attributeKey, String attributeValue) {
        model.addAttribute(attributeKey, attributeValue);
        response.setStatus(HttpStatus.NOT_FOUND.value());
        return "error";
    }
}
