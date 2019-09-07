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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import static java.nio.charset.StandardCharsets.UTF_8;

public class AccountSavingAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private SavedRequestAwareAuthenticationSuccessHandler redirectingHandler;
    private CurrentUserCookieFactory currentUserCookieFactory;
    private Logger logger = LoggerFactory.getLogger(AccountSavingAuthenticationSuccessHandler.class);

    @Autowired
    public AccountSavingAuthenticationSuccessHandler(SavedRequestAwareAuthenticationSuccessHandler redirectingHandler, CurrentUserCookieFactory currentUserCookieFactory) {
        this.redirectingHandler = redirectingHandler;
        this.currentUserCookieFactory = currentUserCookieFactory;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        setSavedAccountOptionCookie(request, response, authentication);
        redirectingHandler.onAuthenticationSuccess(request, response, authentication);
    }

    public void setSavedAccountOptionCookie(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IllegalArgumentException {
        Object principal = authentication.getPrincipal();
        if(!(principal instanceof UaaPrincipal)) {
            throw new IllegalArgumentException("Unrecognized authentication principle.");
        }

        UaaPrincipal uaaPrincipal = (UaaPrincipal) principal;
        if(IdentityZoneHolder.get().getConfig().isAccountChooserEnabled()) {
            SavedAccountOption savedAccountOption = new SavedAccountOption();
            savedAccountOption.setEmail(uaaPrincipal.getEmail());
            savedAccountOption.setOrigin(uaaPrincipal.getOrigin());
            savedAccountOption.setUserId(uaaPrincipal.getId());
            savedAccountOption.setUsername(uaaPrincipal.getName());
            Cookie savedAccountCookie = new Cookie("Saved-Account-" + uaaPrincipal.getId(), encodeCookieValue(JsonUtils.writeValueAsString(savedAccountOption)));
            savedAccountCookie.setPath(request.getContextPath() + "/login");
            savedAccountCookie.setHttpOnly(true);
            savedAccountCookie.setSecure(request.isSecure());
            // cookie expires in a year
            savedAccountCookie.setMaxAge(365*24*60*60);

            response.addCookie(savedAccountCookie);
        }

        Cookie currentUserCookie = null;
        try {
            currentUserCookie = currentUserCookieFactory.getCookie(uaaPrincipal);
        } catch (CurrentUserCookieFactory.CurrentUserCookieEncodingException e) {
            logger.error(String.format("There was an error while creating the Current-Account cookie for user %s", uaaPrincipal.getId()), e);
        }
        response.addCookie(currentUserCookie);
    }

    public static String encodeCookieValue(String inValue) throws IllegalArgumentException {
        String out = null;
        try {
            out = URLEncoder.encode(inValue, UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e);
        }
        return out;
    }
}
