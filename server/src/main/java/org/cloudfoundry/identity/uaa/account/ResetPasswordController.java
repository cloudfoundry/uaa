/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChange;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import javax.servlet.http.HttpServletRequest;
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
    private final Pattern emailPattern;
    private final ExpiringCodeStore codeStore;
    private final UaaUserDatabase userDatabase;
    private final AccountSavingAuthenticationSuccessHandler successHandler;

    public ResetPasswordController(ResetPasswordService resetPasswordService,
                                   MessageService messageService,
                                   TemplateEngine templateEngine,
                                   ExpiringCodeStore codeStore,
                                   UaaUserDatabase userDatabase, AccountSavingAuthenticationSuccessHandler successHandler) {
        this.resetPasswordService = resetPasswordService;
        this.messageService = messageService;
        this.templateEngine = templateEngine;
        this.successHandler = successHandler;
        emailPattern = Pattern.compile("^\\S+@\\S+\\.\\S+$");
        this.codeStore = codeStore;
        this.userDatabase = userDatabase;
    }

    @RequestMapping(value = "/forgot_password", method = RequestMethod.GET)
    public String forgotPasswordPage(Model model,
                                     @RequestParam(required = false, value = "client_id") String clientId,
                                     @RequestParam(required = false, value = "redirect_uri") String redirectUri,
                                     HttpServletResponse response) {
        if(!IdentityZoneHolder.get().getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled()) {
            return handleSelfServiceDisabled(model, response, "error_message_code", "self_service_disabled");
        }
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        return "forgot_password";
    }

    @RequestMapping(value = "/forgot_password.do", method = RequestMethod.POST)
    public String forgotPassword(Model model, @RequestParam("username") String username, @RequestParam(value = "client_id", defaultValue = "") String clientId,
                                 @RequestParam(value = "redirect_uri", defaultValue = "") String redirectUri, HttpServletResponse response) {
        if(!IdentityZoneHolder.get().getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled()) {
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
            logger.error("User with email address " + username + " not found.");
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

    private String getCodeSentEmailHtml(String code) {
        String resetUrl = UaaUrlUtils.getUaaUrl("/reset_password");

        final Context ctx = new Context();
        ctx.setVariable("serviceName", getServiceName());
        ctx.setVariable("code", code);
        ctx.setVariable("resetUrl", resetUrl);
        return templateEngine.process("reset_password", ctx);
    }

    private String getResetUnavailableEmailHtml(String email) {
        String hostname = UaaUrlUtils.getUaaHost();

        final Context ctx = new Context();
        ctx.setVariable("serviceName", getServiceName());
        ctx.setVariable("email", email);
        ctx.setVariable("hostname", hostname);
        return templateEngine.process("reset_password_unavailable", ctx);
    }

    private String getServiceName() {
        if (IdentityZoneHolder.get().equals(IdentityZone.getUaa())) {
            String companyName = IdentityZoneHolder.resolveBranding().getCompanyName();
            return StringUtils.hasText(companyName) ? companyName : "Cloud Foundry";
        } else {
            return IdentityZoneHolder.get().getName();
        }
    }

    @RequestMapping(value = "/email_sent", method = RequestMethod.GET)
    public String emailSentPage(@ModelAttribute("code") String code) {
        return "email_sent";
    }

    @RequestMapping(value = "/reset_password", method = RequestMethod.GET, params = { "code" })
    public String resetPasswordPage(Model model,
                                    HttpServletResponse response,
                                    @RequestParam("code") String code) {

        ExpiringCode expiringCode = checkIfUserExists(codeStore.retrieveCode(code));
        if (expiringCode==null) {
            return handleUnprocessableEntity(model, response, "message_code", "bad_code");
        } else {
            PasswordChange passwordChange = JsonUtils.readValue(expiringCode.getData(), PasswordChange.class);
            String userId = passwordChange.getUserId();
            UaaUser uaaUser = userDatabase.retrieveUserById(userId);
            String newCode = codeStore.generateCode(expiringCode.getData(), new Timestamp(System.currentTimeMillis() + (10 * 60 * 1000)), expiringCode.getIntent()).getCode();
            model.addAttribute("code", newCode);
            model.addAttribute("email", uaaUser.getEmail());
            return "reset_password";
        }
    }

    public ExpiringCode checkIfUserExists(ExpiringCode code) {
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
