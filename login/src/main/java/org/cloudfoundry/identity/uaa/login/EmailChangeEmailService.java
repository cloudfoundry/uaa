package org.cloudfoundry.identity.uaa.login;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.scim.endpoints.ChangeEmailEndpoints;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

public class EmailChangeEmailService implements ChangeEmailService {

    private final TemplateEngine templateEngine;
    private final MessageService messageService;
    private final String brand;
    private final ChangeEmailEndpoints endpoints;

    public EmailChangeEmailService(TemplateEngine templateEngine, MessageService messageService, String brand, ChangeEmailEndpoints endpoints) {
        this.templateEngine = templateEngine;
        this.messageService = messageService;
        this.brand = brand;
        this.endpoints = endpoints;
    }

    @Override
    public void beginEmailChange(String userId, String email, String newEmail, String clientId) {
        Map<String,String> request = new HashMap<>();
        request.put("userId", userId);
        request.put("email", newEmail);
        request.put("client_id", clientId);
        ChangeEmailEndpoints.EmailChange change = new ChangeEmailEndpoints.EmailChange();
        change.setClientId(clientId);
        change.setEmail(newEmail);
        change.setUserId(userId);
        ResponseEntity<String> result = endpoints.generateEmailVerificationCode(change);
        String htmlContent = null;
        if (result.getStatusCode()== HttpStatus.CONFLICT) {
            throw new UaaException("Conflict", 409);
        } else if (result.getStatusCode()==HttpStatus.CREATED) {
            htmlContent = getEmailChangeEmailHtml(email, newEmail, result.getBody());
        }

        if(htmlContent != null) {
            String subject = getSubjectText();
            messageService.sendMessage(null, newEmail, MessageType.CHANGE_EMAIL, subject, htmlContent);
        }
    }

    @Override
    public Map<String, String> completeVerification(String code) {
        ResponseEntity<ChangeEmailEndpoints.EmailChangeResponse> responseEntity;
        ChangeEmailEndpoints.EmailChangeResponse response = null;
        try {
            responseEntity = endpoints.changeEmail(code);
            if (responseEntity.getStatusCode()==HttpStatus.OK) {
                response = responseEntity.getBody();
            } else {
                throw new UaaException("Error",responseEntity.getStatusCode().value());
            }
        } catch (IOException e) {
            throw new UaaException(e.getMessage(), e);
        }
        Map<String,String> result = new HashMap<>();
        result.put("userId", response.getUserId());
        result.put("username", response.getUsername());
        result.put("email",response.getEmail());
        if (StringUtils.hasText(response.getRedirectUrl())) {
            result.put("redirect_url", response.getRedirectUrl());
        }
        return result;
    }

    private String getSubjectText() {
        return "Email change verification";
    }

    private String getEmailChangeEmailHtml(String email, String newEmail, String code) {
        String verifyUrl = ServletUriComponentsBuilder.fromCurrentContextPath().path("/verify_email").build().toUriString();

        final Context ctx = new Context();
        ctx.setVariable("serviceName", brand.equals("pivotal") ? "Pivotal " : "Cloud Foundry");
        ctx.setVariable("servicePhrase", brand.equals("pivotal") ? "a Pivotal ID" : "an account");
        ctx.setVariable("code", code);
        ctx.setVariable("newEmail", newEmail);
        ctx.setVariable("email", email);
        ctx.setVariable("verifyUrl", verifyUrl);
        return templateEngine.process("verify_email", ctx);
    }

}
