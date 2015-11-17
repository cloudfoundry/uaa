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
package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.error.ExceptionReport;
import org.cloudfoundry.identity.uaa.error.InvalidCodeException;
import org.cloudfoundry.identity.uaa.login.ConflictException;
import org.cloudfoundry.identity.uaa.login.ForgotPasswordInfo;
import org.cloudfoundry.identity.uaa.login.NotFoundException;
import org.cloudfoundry.identity.uaa.login.ResetPasswordService;
import org.cloudfoundry.identity.uaa.login.ResetPasswordService.ResetPasswordResponse;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;

@Controller
public class PasswordResetEndpoint {

    private final ResetPasswordService resetPasswordService;
    private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(new HttpMessageConverter<?>[0]);
    private ExpiringCodeStore codeStore;

    public PasswordResetEndpoint(ResetPasswordService resetPasswordService) {
        this.resetPasswordService = resetPasswordService;
    }

    public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
        this.messageConverters = messageConverters;
    }

    @RequestMapping(value = "/password_resets", method = RequestMethod.POST)
    public ResponseEntity<Map<String,String>> resetPassword(@RequestBody String email,
                                                            @RequestParam(required=false, value = "client_id") String clientId,
                                                            @RequestParam(required=false, value = "redirect_uri") String redirectUri) throws IOException {
        if (clientId == null) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication instanceof OAuth2Authentication) {
                OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;
                clientId = oAuth2Authentication.getOAuth2Request().getClientId();
            }
        }
        Map<String,String> response = new HashMap<>();
        try {
            ForgotPasswordInfo forgotPasswordInfo = resetPasswordService.forgotPassword(email, clientId, redirectUri);
            response.put("code", forgotPasswordInfo.getResetPasswordCode().getCode());
            response.put("user_id", forgotPasswordInfo.getUserId());
            return new ResponseEntity<>(response, CREATED);
        } catch (ConflictException e) {
            response.put("user_id", e.getUserId());
            return new ResponseEntity<>(response, CONFLICT);
        } catch (NotFoundException e) {
            return new ResponseEntity<>(NOT_FOUND);
        }
    }

    @RequestMapping(value = "/password_change", method = RequestMethod.POST)
    public ResponseEntity<Map<String,String>> changePassword(@RequestBody PasswordReset passwordReset) {
        ResponseEntity<Map<String,String>> responseEntity;
        if (passwordReset.getCode() != null) {
            try {
                ResetPasswordResponse response = resetPasswordService.resetPassword(passwordReset.getCode(), passwordReset.getNewPassword());
                ScimUser user = response.getUser();
                ExpiringCode loginCode = getCode(user.getId(), user.getUserName(), response.getClientId());
                Map<String, String> responseBody = new HashMap<>();
                responseBody.put("user_id", user.getId());
                responseBody.put("username", user.getUserName());
                responseBody.put("email", user.getPrimaryEmail());
                responseBody.put("code", loginCode.getCode());
                return new ResponseEntity<>(responseBody, OK);
            } catch (BadCredentialsException e) {
                return new ResponseEntity<>(UNAUTHORIZED);
            } catch (ScimResourceNotFoundException e) {
                return new ResponseEntity<>(NOT_FOUND);
            } catch (InvalidPasswordException | InvalidCodeException e) {
                throw e;
            } catch (Exception e) {
                return new ResponseEntity<>(INTERNAL_SERVER_ERROR);
            }
        } else {
            responseEntity = new ResponseEntity<>(BAD_REQUEST);
        }
        return responseEntity;
    }

    private ExpiringCode getCode(String id, String username, String clientId) {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", id);
        codeData.put("username", username);
        codeData.put(OAuth2Utils.CLIENT_ID, clientId);
        codeData.put(OriginKeys.ORIGIN, OriginKeys.UAA);
        codeData.put("action", ExpiringCodeType.AUTOLOGIN.name());
        return codeStore.generateCode(JsonUtils.writeValueAsString(codeData), new Timestamp(System.currentTimeMillis() + 5 * 60 * 1000));
    }

    @ExceptionHandler(InvalidPasswordException.class)
    public View handleException(InvalidPasswordException t) throws ScimException {
        return new ConvertingExceptionView(new ResponseEntity<>(new ExceptionReport(
                t, false), UNPROCESSABLE_ENTITY),
                messageConverters);
    }

    @ExceptionHandler(InvalidCodeException.class)
    public View handleCodeException(InvalidCodeException t) throws ScimException {
        return new ConvertingExceptionView(new ResponseEntity<>(new ExceptionReport(
            t, false), UNPROCESSABLE_ENTITY),
            messageConverters);
    }

    public void setCodeStore(ExpiringCodeStore codeStore) {
        this.codeStore = codeStore;
    }
}
