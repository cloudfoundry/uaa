/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.LinkedList;

import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@Controller
public class ForcePasswordChangeController {

    private ResourcePropertySource resourcePropertySource;

    public static final String FORCE_PASSWORD_EXPIRED_USER = "FORCE_PASSWORD_EXPIRED_USER";
    private Log logger = LogFactory.getLog(getClass());

    public void setSuccessHandler(AccountSavingAuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    @Autowired
    @Qualifier("accountSavingAuthenticationSuccessHandler")
    private AccountSavingAuthenticationSuccessHandler successHandler;

    @Autowired
    @Qualifier("resetPasswordService")
    private ResetPasswordService resetPasswordService;

    @RequestMapping(value="/force_password_change", method= GET)
    public String forcePasswordChangePage(Model model, HttpSession session) throws IOException {
        if(session.getAttribute(FORCE_PASSWORD_EXPIRED_USER) == null) {
            return "redirect:/login";
        }
        String email = ((UaaAuthentication)session.getAttribute(FORCE_PASSWORD_EXPIRED_USER)).getPrincipal().getEmail();
        model.addAttribute("email", email);
        return "force_password_change";
    }

    @RequestMapping(value="/force_password_change", method = POST)
    public String handleForcePasswordChange(Model model,
                                            @RequestParam("password")  String password,
                                            @RequestParam("password_confirmation") String passwordConfirmation,
                                            HttpServletRequest request,
                                            HttpServletResponse response,
                                            HttpSession session) throws IOException {
        if(session.getAttribute(FORCE_PASSWORD_EXPIRED_USER) == null) {
            return "redirect:" + request.getContextPath()+"/login";
        }
        UaaAuthentication authentication = ((UaaAuthentication)session
            .getAttribute(FORCE_PASSWORD_EXPIRED_USER));
        UaaPrincipal principal = authentication.getPrincipal();

        String email = principal.getEmail();

        PasswordConfirmationValidation validation =
            new PasswordConfirmationValidation(email, password, passwordConfirmation);
        if(!validation.valid()) {
            return handleUnprocessableEntity(model, response, email, resourcePropertySource.getProperty("force_password_change.form_error").toString());
        }
        logger.debug("Processing handleForcePasswordChange for user: "+ email);
        try {
            resetPasswordService.resetUserPassword(principal.getId(), password);
        } catch(InvalidPasswordException exception) {
            return handleUnprocessableEntity(model, response, email, exception.getMessagesAsOneString());
        }
        SavedRequest savedRequest = (SavedRequest) request.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);

        request.getSession().invalidate();
        request.getSession(true);
        if (authentication instanceof UaaAuthentication) {
            UaaAuthentication uaaAuthentication = (UaaAuthentication)authentication;
            authentication = new UaaAuthentication(
                uaaAuthentication.getPrincipal(),
                new LinkedList<>(uaaAuthentication.getAuthorities()),
                new UaaAuthenticationDetails(request)
            );
            ofNullable(successHandler).ifPresent(handler ->
                handler.setSavedAccountOptionCookie(request, response, uaaAuthentication)
            );
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);

        if(savedRequest != null) {
            return "redirect:" + savedRequest.getRedirectUrl();
        } else {
            return "redirect:/";
        }
    }

    public void setResetPasswordService(ResetPasswordService resetPasswordService) {
        this.resetPasswordService = resetPasswordService;
    }

    private String handleUnprocessableEntity(Model model, HttpServletResponse response, String email, String message) {
        model.addAttribute("message", message);
        model.addAttribute("email",  email);
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        return "force_password_change";
    }

    public void setResourcePropertySource(ResourcePropertySource resourcePropertySource) {
        this.resourcePropertySource = resourcePropertySource;
    }
}
