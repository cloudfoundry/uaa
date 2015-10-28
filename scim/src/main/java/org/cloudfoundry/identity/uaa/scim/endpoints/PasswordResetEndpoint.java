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

import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.error.ExceptionReport;
import org.cloudfoundry.identity.uaa.login.ConflictException;
import org.cloudfoundry.identity.uaa.login.ForgotPasswordInfo;
import org.cloudfoundry.identity.uaa.login.NotFoundException;
import org.cloudfoundry.identity.uaa.login.ResetPasswordService;
import org.cloudfoundry.identity.uaa.login.ResetPasswordService.ResetPasswordResponse;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

import java.io.IOException;
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

    public PasswordResetEndpoint(ResetPasswordService resetPasswordService) {
        this.resetPasswordService = resetPasswordService;
    }

    public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
        this.messageConverters = messageConverters;
    }

    @RequestMapping(value = "/password_resets", method = RequestMethod.POST)
    public ResponseEntity<Map<String,String>> resetPassword(@RequestBody String email) throws IOException {
        Map<String,String> response = new HashMap<>();
        try {
            ForgotPasswordInfo forgotPasswordInfo = resetPasswordService.forgotPassword(email, "", "");
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
            responseEntity = resetPassword(passwordReset.getCode(), passwordReset.getNewPassword());
        } else {
            responseEntity = new ResponseEntity<>(BAD_REQUEST);
        }
        return responseEntity;
    }

    private ResponseEntity<Map<String, String>> resetPassword(String code, String newPassword) {
        try {
            ResetPasswordResponse response = resetPasswordService.resetPassword(code, newPassword);
            ScimUser user = response.getUser();
            Map<String, String> userInfo = new HashMap<>();
            userInfo.put("user_id", user.getId());
            userInfo.put("username", user.getUserName());
            userInfo.put("email", user.getPrimaryEmail());
            return new ResponseEntity<>(userInfo, OK);
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(UNAUTHORIZED);
        } catch (ScimResourceNotFoundException e) {
            return new ResponseEntity<>(NOT_FOUND);
        } catch (InvalidPasswordException e) {
            throw e;
        } catch (Exception e) {
            return new ResponseEntity<>(INTERNAL_SERVER_ERROR);
        }
    }

    @ExceptionHandler(InvalidPasswordException.class)
    public View handleException(InvalidPasswordException t) throws ScimException {
        return new ConvertingExceptionView(new ResponseEntity<>(new ExceptionReport(
                t, false), UNPROCESSABLE_ENTITY),
                messageConverters);
    }
}
