/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.ResetPasswordService.ResetPasswordResponse;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.sql.Timestamp;
import java.util.Map;
import java.util.regex.Pattern;

import static org.springframework.util.StringUtils.hasText;

@Controller
public class ResetPasswordController {
    protected final Log logger = LogFactory.getLog(getClass());

    private final ResetPasswordService resetPasswordService;
    private final MessageService messageService;
    private final TemplateEngine templateEngine;
    private final UaaUrlUtils uaaUrlUtils;
    private final String brand;
    private final Pattern emailPattern;
    private final ExpiringCodeStore codeStore;
    private final UaaUserDatabase userDatabase;

    public ResetPasswordController(ResetPasswordService resetPasswordService,
                                   MessageService messageService,
                                   TemplateEngine templateEngine,
                                   UaaUrlUtils uaaUrlUtils,
                                   String brand,
                                   ExpiringCodeStore codeStore,
                                   UaaUserDatabase userDatabase) {
        this.resetPasswordService = resetPasswordService;
        this.messageService = messageService;
        this.templateEngine = templateEngine;
        this.uaaUrlUtils = uaaUrlUtils;
        this.brand = brand;
        emailPattern = Pattern.compile("^\\S+@\\S+\\.\\S+$");
        this.codeStore = codeStore;
        this.userDatabase = userDatabase;
    }

    @RequestMapping(value = "/forgot_password", method = RequestMethod.GET)
    public String forgotPasswordPage(Model model,
                                     @RequestParam(required = false, value = "client_id") String clientId,
                                     @RequestParam(required = false, value = "redirect_uri") String redirectUri) {
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        return "forgot_password";
    }

    @RequestMapping(value = "/forgot_password.do", method = RequestMethod.POST)
    public String forgotPassword(Model model, @RequestParam("email") String email, @RequestParam(value = "client_id", defaultValue = "") String clientId,
                                 @RequestParam(value = "redirect_uri", defaultValue = "") String redirectUri, HttpServletResponse response) {
        if (emailPattern.matcher(email).matches()) {
            forgotPassword(email, clientId, redirectUri);
            return "redirect:email_sent?code=reset_password";
        } else {
            return handleUnprocessableEntity(model, response, "message_code", "form_error");
        }
    }

    private void forgotPassword(String email, String clientId, String redirectUri) {
        String subject = getSubjectText();
        String htmlContent = null;
        String userId = null;

        try {
            ForgotPasswordInfo forgotPasswordInfo = resetPasswordService.forgotPassword(email, clientId, redirectUri);
            userId = forgotPasswordInfo.getUserId();
            htmlContent = getCodeSentEmailHtml(forgotPasswordInfo.getResetPasswordCode().getCode(), email);
        } catch (ConflictException e) {
            htmlContent = getResetUnavailableEmailHtml(email);
            userId = e.getUserId();
        } catch (NotFoundException e) {
            logger.error("User with email address " + email + " not found.");
        }

        if (htmlContent != null && userId != null) {
            messageService.sendMessage(email, MessageType.PASSWORD_RESET, subject, htmlContent);
        }
    }

    private String getSubjectText() {
        String serviceName = getServiceName();
        if (StringUtils.isEmpty(serviceName)) {
            return "Account password reset request";
        }
        return serviceName + " account password reset request";
    }

    private String getCodeSentEmailHtml(String code, String email) {
        String resetUrl = uaaUrlUtils.getUaaUrl("/reset_password");

        final Context ctx = new Context();
        ctx.setVariable("serviceName", getServiceName());
        ctx.setVariable("code", code);
        ctx.setVariable("email", email);
        ctx.setVariable("resetUrl", resetUrl);
        return templateEngine.process("reset_password", ctx);
    }

    private String getResetUnavailableEmailHtml(String email) {
        String hostname = uaaUrlUtils.getUaaHost();

        final Context ctx = new Context();
        ctx.setVariable("serviceName", getServiceName());
        ctx.setVariable("email", email);
        ctx.setVariable("hostname", hostname);
        return templateEngine.process("reset_password_unavailable", ctx);
    }

    private String getServiceName() {
        if (IdentityZoneHolder.get().equals(IdentityZone.getUaa())) {
            return brand.equals("pivotal") ? "Pivotal" : "";
        } else {
            return IdentityZoneHolder.get().getName();
        }
    }

    @RequestMapping(value = "/email_sent", method = RequestMethod.GET)
    public String emailSentPage(@ModelAttribute("code") String code) {
        return "email_sent";
    }

    @RequestMapping(value = "/reset_password", method = RequestMethod.GET, params = { "email", "code" })
    public String resetPasswordPage(Model model,
                                    HttpServletResponse response,
                                    @RequestParam("code") String code,
                                    @RequestParam("email") String email) {

        ExpiringCode expiringCode = validateUserAndClient(codeStore.retrieveCode(code));
        if (expiringCode==null) {
            return handleUnprocessableEntity(model, response, "message_code", "bad_code");
        } else {
            Timestamp fiveMinutes = new Timestamp(System.currentTimeMillis()+(1000*60*5));
            model.addAttribute("code", codeStore.generateCode(expiringCode.getData(), fiveMinutes).getCode());
            model.addAttribute("email", email);
            return "reset_password";
        }
    }

    public ExpiringCode validateUserAndClient(ExpiringCode code) {
        if (code==null) {
            logger.debug("reset_password ExpiringCode object is null. Aborting.");
            return null;
        }
        if (!hasText(code.getData())) {
            logger.debug("reset_password ExpiringCode["+code.getCode()+"] data string is null or empty. Aborting.");
            return null;
        }
        Map<String,String> data = JsonUtils.readValue(code.getData(), new TypeReference<Map<String,String>>() {});
        if (!hasText(data.get("user_id"))) {
            logger.debug("reset_password ExpiringCode["+code.getCode()+"] user_id string is null or empty. Aborting.");
            return null;
        }
        String userId = data.get("user_id");
        try {
            userDatabase.retrieveUserById(userId);
        } catch (UsernameNotFoundException e) {
            logger.debug("reset_password ExpiringCode["+code.getCode()+"] user_id is invalid. Aborting.");
            return null;
        }
        return code;
    }

    @RequestMapping(value = "/reset_password.do", method = RequestMethod.POST)
    public String resetPassword(Model model,
                                @RequestParam("code") String code,
                                @RequestParam("email") String email,
                                @RequestParam("password") String password,
                                @RequestParam("password_confirmation") String passwordConfirmation,
                                HttpServletResponse response,
                                HttpSession session) {

        PasswordConfirmationValidation validation = new PasswordConfirmationValidation(password, passwordConfirmation);
        if (!validation.valid()) {
            model.addAttribute("message_code", validation.getMessageCode());
            model.addAttribute("email", email);
            model.addAttribute("code", code);
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return "reset_password";
        }

        try {
            ResetPasswordResponse  resetPasswordResponse = resetPasswordService.resetPassword(code, password);
            ScimUser user = resetPasswordResponse.getUser();
            UaaPrincipal uaaPrincipal = new UaaPrincipal(user.getId(), user.getUserName(), user.getPrimaryEmail(), Origin.UAA, null, IdentityZoneHolder.get().getId());
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
            SecurityContextHolder.getContext().setAuthentication(token);

            String redirectLocation = resetPasswordResponse.getRedirectUri();
            SavedRequest savedRequest = (SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
            if (redirectLocation.equals("home") && savedRequest != null && savedRequest.getRedirectUrl() != null) {
                redirectLocation = savedRequest.getRedirectUrl();
            }

            return "redirect:" + redirectLocation;
        } catch (UaaException e) {
            return handleUnprocessableEntity(model, response, "message_code", "bad_code");
        } catch (InvalidPasswordException e) {
            return handleUnprocessableEntity(model, response, "message", e.getMessagesAsOneString());
        }
    }

    private String handleUnprocessableEntity(Model model, HttpServletResponse response, String attributeKey, String attributeValue) {
        model.addAttribute(attributeKey, attributeValue);
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        return "forgot_password";
    }
}
