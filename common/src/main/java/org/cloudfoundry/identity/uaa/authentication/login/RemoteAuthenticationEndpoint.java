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

package org.cloudfoundry.identity.uaa.authentication.login;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * A username/password authentication endpoint (only intended) for use by the
 * login server.
 *
 * @author Luke Taylor
 */
@Controller
public class RemoteAuthenticationEndpoint {
    private final Log logger = LogFactory.getLog(getClass());

    private AuthenticationManager authenticationManager;
    private AuthenticationManager loginAuthenticationManager;

    public void setLoginAuthenticationManager(AuthenticationManager loginAuthenticationManager) {
        this.loginAuthenticationManager = loginAuthenticationManager;
    }

    public RemoteAuthenticationEndpoint(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @RequestMapping(value = { "/authenticate" }, method = RequestMethod.POST)
    @ResponseBody
    public HttpEntity<Map<String, String>> authenticate(HttpServletRequest request,
                    @RequestParam(value = "username", required = true) String username,
                    @RequestParam(value = "password", required = true) String password) {
        Map<String, String> responseBody = new HashMap<>();

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        token.setDetails(new UaaAuthenticationDetails(request));

        HttpStatus status = HttpStatus.UNAUTHORIZED;
        try {
            Authentication a = authenticationManager.authenticate(token);
            responseBody.put("username", a.getName());
            if (a.getPrincipal() != null && a.getPrincipal() instanceof UaaPrincipal) {
                responseBody.put("email", ((UaaPrincipal) a.getPrincipal()).getEmail());
            }
            processAdditionalInformation(responseBody, a);
            status = HttpStatus.OK;
        } catch (AccountNotVerifiedException e) {
            responseBody.put("error", "account not verified");
            status = HttpStatus.FORBIDDEN;
        } catch (AuthenticationException e) {
            responseBody.put("error", "authentication failed");
        } catch (Exception e) {
            logger.debug("Failed to authenticate user ", e);
            responseBody.put("error", "error");
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }

        return new ResponseEntity<>(responseBody, status);
    }

    @RequestMapping(value = { "/authenticate" }, method = RequestMethod.POST, params = {"source","origin", UaaAuthenticationDetails.ADD_NEW})
    @ResponseBody
    public HttpEntity<Map<String, String>> authenticate(HttpServletRequest request,
                                                        @RequestParam(value = "username", required = true) String username,
                                                        @RequestParam(value = OriginKeys.ORIGIN, required = true) String origin,
                                                        @RequestParam(value = "email", required = false) String email) {
        Map<String, String> responseBody = new HashMap<>();
        HttpStatus status = HttpStatus.UNAUTHORIZED;

        if (!hasClientOauth2Authentication()) {
            responseBody.put("error", "authentication failed");
            return new ResponseEntity<>(responseBody, status);
        }

        Map<String, String> userInfo = new HashMap<>();
        userInfo.put("username", username);
        userInfo.put(OriginKeys.ORIGIN, origin);
        if (StringUtils.hasText(email)) {
            userInfo.put("email", email);
        }

        AuthzAuthenticationRequest token = new AuthzAuthenticationRequest(userInfo, new UaaAuthenticationDetails(request));
        try {
            Authentication a = loginAuthenticationManager.authenticate(token);
            responseBody.put("username", a.getName());
            processAdditionalInformation(responseBody, a);
            status = HttpStatus.OK;
        } catch (AuthenticationException e) {
            responseBody.put("error", "authentication failed");
        } catch (Exception e) {
            logger.debug("Failed to authenticate user ", e);
            responseBody.put("error", "error");
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }

        return new ResponseEntity<>(responseBody, status);
    }

    private void processAdditionalInformation(Map<String, String> responseBody, Authentication a) {
        if (hasClientOauth2Authentication()) {
            UaaPrincipal principal = getPrincipal(a);
            if (principal!=null) {
                responseBody.put(OriginKeys.ORIGIN, principal.getOrigin());
                responseBody.put("user_id", principal.getId());
            }
        }
    }

    protected UaaPrincipal getPrincipal(Authentication a) {
        if (a.getPrincipal() instanceof UaaPrincipal) {
            return (UaaPrincipal)a.getPrincipal();
        } else {
            return null;
        }
    }

    protected boolean hasClientOauth2Authentication() {
        SecurityContext context = SecurityContextHolder.getContext();

        if (context.getAuthentication() instanceof OAuth2Authentication) {
            OAuth2Authentication authentication = (OAuth2Authentication) context.getAuthentication();
            if (authentication.isClientOnly()) {
                return true;
            }
        }
        return false;
    }
}
