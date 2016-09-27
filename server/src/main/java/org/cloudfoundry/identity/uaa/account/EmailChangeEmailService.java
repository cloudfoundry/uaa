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

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.util.StringUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.EMAIL;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.findMatchingRedirectUri;

public class EmailChangeEmailService implements ChangeEmailService {

    private final TemplateEngine templateEngine;
    private final MessageService messageService;
    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore codeStore;
    private final ClientDetailsService clientDetailsService;
    private static final int EMAIL_CHANGE_LIFETIME = 30 * 60 * 1000;
    public static final String CHANGE_EMAIL_REDIRECT_URL = "change_email_redirect_url";

    public EmailChangeEmailService(TemplateEngine templateEngine, MessageService messageService, ScimUserProvisioning scimUserProvisioning, ExpiringCodeStore codeStore, ClientDetailsService clientDetailsService) {
        this.templateEngine = templateEngine;
        this.messageService = messageService;
        this.scimUserProvisioning = scimUserProvisioning;
        this.codeStore = codeStore;
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    public void beginEmailChange(String userId, String email, String newEmail, String clientId, String redirectUri) {
        ScimUser user = scimUserProvisioning.retrieve(userId);
        List<ScimUser> results = scimUserProvisioning.query("userName eq \"" + newEmail + "\" and origin eq \"" + OriginKeys.UAA + "\"");

        if (user.getUserName().equals(user.getPrimaryEmail())) {
            if (!results.isEmpty()) {
                throw new UaaException("Conflict", 409);
            }
        }

        String code = generateExpiringCode(userId, newEmail, clientId, redirectUri);
        String htmlContent = getEmailChangeEmailHtml(email, newEmail, code);

        if(htmlContent != null) {
            String subject = getSubjectText();
            messageService.sendMessage(newEmail, MessageType.CHANGE_EMAIL, subject, htmlContent);
        }
    }

    private String generateExpiringCode(String userId, String newEmail, String clientId, String redirectUri) {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", userId);
        codeData.put("client_id", clientId);
        codeData.put("redirect_uri", redirectUri);
        codeData.put("email", newEmail);

        return codeStore.generateCode(JsonUtils.writeValueAsString(codeData), new Timestamp(System.currentTimeMillis() + EMAIL_CHANGE_LIFETIME), EMAIL.name()).getCode();
    }

    @Override
    public Map<String, String> completeVerification(String code) {
        ExpiringCode expiringCode = codeStore.retrieveCode(code);
        if ((null == expiringCode) || ((null != expiringCode.getIntent()) && !EMAIL.name().equals(expiringCode.getIntent()))) {
            throw new UaaException("Error", 400);
        }

        Map<String, String> codeData = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
        String userId = codeData.get("user_id");
        String email = codeData.get("email");
        ScimUser user = scimUserProvisioning.retrieve(userId);

        if (user.getUserName().equals(user.getPrimaryEmail())) {
            user.setUserName(email);
        }
        user.getEmails().clear();
        user.setPrimaryEmail(email);
        scimUserProvisioning.update(userId, user);

        String clientId = codeData.get("client_id");
        String redirectLocation = null;

        if (clientId != null) {
            String redirectUri = codeData.get("redirect_uri") == null ? "" : codeData.get("redirect_uri");

            try {
                ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
                Set<String> redirectUris = clientDetails.getRegisteredRedirectUri() == null ? Collections.emptySet() :
                        clientDetails.getRegisteredRedirectUri();
                String changeEmailRedirectUrl = (String) clientDetails.getAdditionalInformation().get(CHANGE_EMAIL_REDIRECT_URL);
                redirectLocation = findMatchingRedirectUri(redirectUris, redirectUri, changeEmailRedirectUrl);
            } catch (NoSuchClientException nsce) {}
        }

        Map<String,String> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("username", user.getUserName());
        result.put("email", user.getPrimaryEmail());
        result.put("redirect_url", redirectLocation);
        return result;
    }

    private String getSubjectText() {
        if (IdentityZoneHolder.get().equals(IdentityZone.getUaa())) {
            String companyName = IdentityZoneHolder.resolveBranding().getCompanyName();
            return StringUtils.hasText(companyName) ? companyName + " Email change verification" : "Account Email change verification";
        }
        else {
            return IdentityZoneHolder.get().getName() + " Email change verification";
        }
    }

    private String getEmailChangeEmailHtml(String email, String newEmail, String code) {
        String verifyUrl = UaaUrlUtils.getUaaUrl("/verify_email");

        final Context ctx = new Context();
        if (IdentityZoneHolder.get().equals(IdentityZone.getUaa())) {
            String companyName = IdentityZoneHolder.resolveBranding().getCompanyName();
            ctx.setVariable("serviceName", StringUtils.hasText(companyName) ? companyName : "Cloud Foundry");
            ctx.setVariable("servicePhrase", StringUtils.hasText(companyName) ? "a " + companyName + " account" : "an account");
        }
        else {
            ctx.setVariable("serviceName", IdentityZoneHolder.get().getName());
            ctx.setVariable("servicePhrase", IdentityZoneHolder.get().getName());
        }
        ctx.setVariable("code", code);
        ctx.setVariable("newEmail", newEmail);
        ctx.setVariable("email", email);
        ctx.setVariable("verifyUrl", verifyUrl);
        return templateEngine.process("verify_email", ctx);
    }

}
