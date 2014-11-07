package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpMethod.POST;

public class EmailChangeEmailService implements ChangeEmailService {

    private final TemplateEngine templateEngine;
    private final MessageService messageService;
    private final RestTemplate uaaTemplate;
    private final String uaaBaseUrl;
    private final String brand;

    public EmailChangeEmailService(TemplateEngine templateEngine, MessageService messageService, RestTemplate uaaTemplate, String uaaBaseUrl, String brand) {
        this.templateEngine = templateEngine;
        this.messageService = messageService;
        this.uaaTemplate = uaaTemplate;
        this.uaaBaseUrl = uaaBaseUrl;
        this.brand = brand;
    }

    @Override
    public void beginEmailChange(String userId, String email, String newEmail, String clientId) {
        Map<String,String> request = new HashMap<>();
        request.put("userId", userId);
        request.put("email", newEmail);
        request.put("client_id", clientId);
        String expiringCode;
        try {
            expiringCode = uaaTemplate.postForObject(uaaBaseUrl + "/email_verifications", request, String.class);
        } catch (HttpClientErrorException e) {
            throw new UaaException(e.getStatusText(), e.getStatusCode().value());
        }
        String subject = getSubjectText();
        String htmlContent = getEmailChangeEmailHtml(email, newEmail, expiringCode);

        if(htmlContent != null) {
            messageService.sendMessage(null, newEmail, MessageType.CHANGE_EMAIL, subject, htmlContent);
        }
    }

    @Override
    public Map<String, String> completeVerification(String code) {
        ResponseEntity<Map<String, String>> responseEntity;
        try {
            responseEntity = uaaTemplate.exchange(uaaBaseUrl + "/email_changes", POST, new HttpEntity<>(code), new ParameterizedTypeReference<Map<String, String>>() {
                });
        } catch (HttpClientErrorException e) {
            throw new UaaException(e.getStatusText(), e.getStatusCode().value());
        }
        return responseEntity.getBody();
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
