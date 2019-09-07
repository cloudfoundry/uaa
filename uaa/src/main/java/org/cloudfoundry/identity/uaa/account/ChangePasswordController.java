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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@Controller
public class ChangePasswordController {

    private final ChangePasswordService changePasswordService;

    public ChangePasswordController(ChangePasswordService changePasswordService) {
        this.changePasswordService = changePasswordService;
    }

    @RequestMapping(value="/change_password", method = GET)
    public String changePasswordPage() {
        return "change_password";
    }

    @RequestMapping(value="/change_password.do", method = POST)
    public String changePassword(
            Model model,
            @RequestParam("current_password") String currentPassword,
            @RequestParam("new_password") String newPassword,
            @RequestParam("confirm_password") String confirmPassword,
            HttpServletResponse response,
            HttpServletRequest request) {

        PasswordConfirmationValidation validation = new PasswordConfirmationValidation(newPassword, confirmPassword);
        if (!validation.valid()) {
            model.addAttribute("message_code", validation.getMessageCode());
            response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
            return "change_password";
        }

        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();
        String username = authentication.getName();

        try {
            changePasswordService.changePassword(username, currentPassword, newPassword);
            request.getSession().invalidate();
            request.getSession(true);
            if (authentication instanceof UaaAuthentication) {
                UaaAuthentication uaaAuthentication = (UaaAuthentication)authentication;
                uaaAuthentication.setAuthenticatedTime(System.currentTimeMillis());
                uaaAuthentication.setAuthenticationDetails(new UaaAuthenticationDetails(request));
            }
            securityContext.setAuthentication(authentication);
            return "redirect:profile";
        } catch (BadCredentialsException e) {
            model.addAttribute("message_code", "unauthorized");
        } catch (InvalidPasswordException e) {
            model.addAttribute("message", e.getMessagesAsOneString());
        }
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());
        return "change_password";
    }
}
