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

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.cloudfoundry.identity.uaa.authentication.InvalidCodeException;
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
    public ResponseEntity<PasswordResetResponse> resetPassword(@RequestBody String email,
                                                               @RequestParam(required = false, value = "client_id") String clientId,
                                                               @RequestParam(required = false, value = "redirect_uri") String redirectUri) throws IOException {
        if (clientId == null) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication instanceof OAuth2Authentication) {
                OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;
                clientId = oAuth2Authentication.getOAuth2Request().getClientId();
            }
        }
        PasswordResetResponse response = new PasswordResetResponse();
        try {
            ForgotPasswordInfo forgotPasswordInfo = resetPasswordService.forgotPassword(email, clientId, redirectUri);
            response.setChangeCode(forgotPasswordInfo.getResetPasswordCode().getCode());
            response.setUserId(forgotPasswordInfo.getUserId());
            return new ResponseEntity<>(response, CREATED);
        } catch (ConflictException e) {
            response.setUserId(e.getUserId());
            return new ResponseEntity<>(response, CONFLICT);
        } catch (NotFoundException e) {
            return new ResponseEntity<>(NOT_FOUND);
        }
    }

    private ExpiringCode getExpiringCode(String code) {
        ExpiringCode expiringCode = codeStore.retrieveCode(code);
        if (expiringCode == null) {
            throw new InvalidCodeException("invalid_code", "Sorry, your reset password link is no longer valid. Please request a new one", 422);
        }
        return expiringCode;
    }

    @RequestMapping(value = "/password_change", method = RequestMethod.POST)
    public ResponseEntity<LostPasswordChangeResponse> changePassword(@RequestBody LostPasswordChangeRequest passwordChangeRequest) {
        ResponseEntity<LostPasswordChangeResponse> responseEntity;
        if (passwordChangeRequest.getChangeCode() != null) {
            try {
                ExpiringCode expiringCode = getExpiringCode(passwordChangeRequest.getChangeCode());
                ResetPasswordService.ResetPasswordResponse reset = resetPasswordService.resetPassword(expiringCode, passwordChangeRequest.getNewPassword());
                ScimUser user = reset.getUser();
                ExpiringCode loginCode = getCode(user.getId(), user.getUserName(), reset.getClientId());
                LostPasswordChangeResponse response = new LostPasswordChangeResponse();
                response.setUserId(user.getId());
                response.setUsername(user.getUserName());
                response.setEmail(user.getPrimaryEmail());
                response.setLoginCode(loginCode.getCode());
                return new ResponseEntity<>(response, OK);
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
        return codeStore.generateCode(JsonUtils.writeValueAsString(codeData), new Timestamp(System.currentTimeMillis() + 5 * 60 * 1000), ExpiringCodeType.AUTOLOGIN.name());
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
