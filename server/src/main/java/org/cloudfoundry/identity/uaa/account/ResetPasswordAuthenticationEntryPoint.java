/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation.PasswordConfirmationException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


public class ResetPasswordAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        Throwable cause = authException.getCause();
        response.setStatus(HttpStatus.UNPROCESSABLE_ENTITY.value());

        HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(request) {
            @Override
            public String getMethod() {
                return "GET";
            }

            @Override
            public String getParameter(String name) {
                if ("code".equals(name)) {
                    return (String) getAttribute(name);
                }
                return super.getParameter(name);
            }

            @Override
            public Map<String, String[]> getParameterMap() {
                Map<String, String[]> map = super.getParameterMap();
                if (map.containsKey("code")) {
                    Map<String, String[]> newMap = new HashMap<>(map);
                    newMap.put("code", new String[]{(String) getAttribute("code")});
                    map = newMap;
                }
                return map;
            }

            @Override
            public String[] getParameterValues(String name) {
                return getParameterMap().get(name);
            }
        };

        if (cause instanceof PasswordConfirmationException passwordConfirmationException) {
            request.setAttribute("message_code", passwordConfirmationException.getMessageCode());

            request.getRequestDispatcher("/reset_password").forward(wrapper, response);
            return;
        } else {
            if (cause instanceof InvalidPasswordException exception) {
                request.setAttribute("message", exception.getMessagesAsOneString());
                request.getRequestDispatcher("/reset_password").forward(wrapper, response);
            } else {
                request.setAttribute("message_code", "bad_code");
                request.getRequestDispatcher("/forgot_password").forward(wrapper, response);
            }
        }
    }
}
