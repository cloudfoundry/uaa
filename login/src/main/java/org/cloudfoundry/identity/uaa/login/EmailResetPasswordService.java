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
package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpoints;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.io.IOException;
import java.util.Map;

public class EmailResetPasswordService implements ResetPasswordService {

    private final Log logger = LogFactory.getLog(getClass());

    private final TemplateEngine templateEngine;
    private final MessageService messageService;
    private final PasswordResetEndpoints passwordResetEndpoints;
    private final UaaUrlUtils uaaUrlUtils;
    private final String brand;

    public EmailResetPasswordService(TemplateEngine templateEngine, MessageService messageService, PasswordResetEndpoints passwordResetEndpoints, UaaUrlUtils uaaUrlUtils, String brand) {
        this.templateEngine = templateEngine;
        this.messageService = messageService;
        this.passwordResetEndpoints = passwordResetEndpoints;
        this.uaaUrlUtils = uaaUrlUtils;
        this.brand = brand;
    }

    @Override
    public void forgotPassword(String email) {
        String subject = getSubjectText();
        String htmlContent = null;
        String userId = null;
        try {
            ResponseEntity<Map<String,String>> response = passwordResetEndpoints.resetPassword(email);
            if (response.getStatusCode()==HttpStatus.CONFLICT) {
                //TODO - file story to refactor and not swallow all errors below
                htmlContent = getResetUnavailableEmailHtml(email);
                userId = response.getBody().get("user_id");
            } else if (response.getStatusCode()==HttpStatus.NOT_FOUND) {
                //TODO noop - previous implementation just logged an error
            } else {
                userId = response.getBody().get("user_id");
                htmlContent = getCodeSentEmailHtml(response.getBody().get("code"), email);
            }
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.CONFLICT) {
                htmlContent = getResetUnavailableEmailHtml(email);
                try {
                    Map<String, String> body = JsonUtils.readValue(e.getResponseBodyAsString(), new TypeReference<Map<String, String>>() {
                    });
                    userId = body.get("user_id");
                } catch (JsonUtils.JsonUtilException ioe) {
                    logger.error("Bad response from UAA", ioe);
                }

            } else {
                logger.info("Exception raised while creating password reset for " + email, e);
            }
        } catch (IOException e) {
            logger.error("Exception raised while creating password reset for " + email, e);
        }

        if (htmlContent != null && userId != null) {
            messageService.sendMessage(userId, email, MessageType.PASSWORD_RESET, subject, htmlContent);
        }
    }

    private String getSubjectText() {
        String serviceName = getServiceName();
        if (StringUtils.isEmpty(serviceName)) {
            return "Account password reset request";
        }
        return serviceName + " account password reset request";
    }

    @Override
    public Map<String, String> resetPassword(String code, String newPassword) {

        try {
            PasswordResetEndpoints.PasswordChange change = new PasswordResetEndpoints.PasswordChange();
            change.setCode(code);
            change.setNewPassword(newPassword);
            ResponseEntity<Map<String, String>> responseEntity = passwordResetEndpoints.changePassword(change);
            if (responseEntity.getStatusCode()==HttpStatus.BAD_REQUEST) {
                throw new UaaException("Invalid password reset request.");
            }
            return responseEntity.getBody();
        } catch (RestClientException e) {
            throw new UaaException(e.getMessage());
        }
    }


    private String getCodeSentEmailHtml(String code, String email) {
        String resetUrl = uaaUrlUtils.getUaaUrl("/reset_password");

        final Context ctx = new Context();
        ctx.setVariable("serviceName", getServiceName());
        ctx.setVariable("code", code);
        ctx.setVariable("email", email);
        ctx.setVariable("resetUrl", resetUrl);
        return templateEngine.process("reset_password", ctx);
    }

    private String getResetUnavailableEmailHtml(String email) {
        String hostname = uaaUrlUtils.getUaaHost();

        final Context ctx = new Context();
        ctx.setVariable("serviceName", getServiceName());
        ctx.setVariable("email", email);
        ctx.setVariable("hostname", hostname);
        return templateEngine.process("reset_password_unavailable", ctx);
    }

    private String getServiceName() {
        if (IdentityZoneHolder.get().equals(IdentityZone.getUaa())) {
            return brand.equals("pivotal") ? "Pivotal" : "";
        }
        else {
            return IdentityZoneHolder.get().getName();
        }
    }
}
