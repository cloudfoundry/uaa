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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@Controller
public class ForcePasswordChangeController {

    private ResourcePropertySource resourcePropertySource;

    public static final String FORCE_PASSWORD_EXPIRED_USER = "FORCE_PASSWORD_EXPIRED_USER";
    private Logger logger = LoggerFactory.getLogger(getClass());


    @Autowired
    @Qualifier("resetPasswordService")
    private ResetPasswordService resetPasswordService;

    @RequestMapping(value="/force_password_change", method= GET)
    public String forcePasswordChangePage(Model model) throws IOException {
        String email = ((UaaAuthentication)SecurityContextHolder.getContext().getAuthentication()).getPrincipal().getEmail();
        model.addAttribute("email", email);
        return "force_password_change";
    }

    @RequestMapping(value="/force_password_change", method = POST)
    public String handleForcePasswordChange(Model model,
                                            @RequestParam("password")  String password,
                                            @RequestParam("password_confirmation") String passwordConfirmation,
                                            HttpServletResponse response) throws IOException {
        UaaAuthentication authentication = ((UaaAuthentication)SecurityContextHolder.getContext().getAuthentication());
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
        logger.debug(String.format("Successful password change for username:%s in zone:%s ",principal.getName(), IdentityZoneHolder.get().getId()));
        authentication.setRequiresPasswordChange(false);
        authentication.setAuthenticatedTime(System.currentTimeMillis());
        return "redirect:/force_password_change_completed";
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
