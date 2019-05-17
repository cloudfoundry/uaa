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
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MergedZoneBrandingInformation;
import org.springframework.context.MessageSource;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.util.StringUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.EMAIL;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.findMatchingRedirectUri;

public class EmailChangeEmailService implements ChangeEmailService {

    private final TemplateEngine templateEngine;
    private final MessageService messageService;
    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore codeStore;
    private final MultitenantClientServices clientDetailsService;
    private final MessageSource messageSource;
    private static final int EMAIL_CHANGE_LIFETIME = 30 * 60 * 1000;
    public static final String CHANGE_EMAIL_REDIRECT_URL = "change_email_redirect_url";

    public EmailChangeEmailService(TemplateEngine templateEngine,
                                   MessageService messageService,
                                   ScimUserProvisioning scimUserProvisioning,
                                   ExpiringCodeStore codeStore,
                                   MultitenantClientServices clientDetailsService,
                                   MessageSource messageSource) {
        this.templateEngine = templateEngine;
        this.messageService = messageService;
        this.scimUserProvisioning = scimUserProvisioning;
        this.codeStore = codeStore;
        this.clientDetailsService = clientDetailsService;
        this.messageSource = messageSource;
    }

    @Override
    public void beginEmailChange(String userId, String email, String newEmail, String clientId, String redirectUri, Locale locale) {
        ScimUser user = scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId());
        List<ScimUser> results = scimUserProvisioning.query("userName eq \"" + newEmail + "\" and origin eq \"" + OriginKeys.UAA + "\"", IdentityZoneHolder.get().getId());

        if (user.getUserName().equals(user.getPrimaryEmail())) {
            if (!results.isEmpty()) {
                throw new UaaException("Conflict", 409);
            }
        }

        String code = generateExpiringCode(userId, newEmail, clientId, redirectUri);
        String htmlContent = getEmailChangeEmailHtml(email, newEmail, code, locale);

        if(htmlContent != null) {
            String subject = getSubjectText(locale);
            messageService.sendMessage(newEmail, MessageType.CHANGE_EMAIL, subject, htmlContent);
        }
    }

    private String generateExpiringCode(String userId, String newEmail, String clientId, String redirectUri) {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", userId);
        codeData.put("client_id", clientId);
        codeData.put("redirect_uri", redirectUri);
        codeData.put("email", newEmail);

        return codeStore.generateCode(JsonUtils.writeValueAsString(codeData), new Timestamp(System.currentTimeMillis() + EMAIL_CHANGE_LIFETIME), EMAIL.name(), IdentityZoneHolder.get().getId()).getCode();
    }

    @Override
    public Map<String, String> completeVerification(String code) {
        ExpiringCode expiringCode = codeStore.retrieveCode(code, IdentityZoneHolder.get().getId());
        if ((null == expiringCode) || ((null != expiringCode.getIntent()) && !EMAIL.name().equals(expiringCode.getIntent()))) {
            throw new UaaException("Error", 400);
        }

        Map<String, String> codeData = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
        String userId = codeData.get("user_id");
        String email = codeData.get("email");
        ScimUser user = scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId());

        if (user.getUserName().equals(user.getPrimaryEmail())) {
            user.setUserName(email);
        }
        user.getEmails().clear();
        user.setPrimaryEmail(email);
        scimUserProvisioning.update(userId, user, IdentityZoneHolder.get().getId());

        String clientId = codeData.get("client_id");
        String redirectLocation = null;

        if (clientId != null) {
            String redirectUri = codeData.get("redirect_uri") == null ? "" : codeData.get("redirect_uri");

            try {
                ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
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

    private String getSubjectText(Locale locale) {
        if (IdentityZoneHolder.isUaa()) {
            String companyName = MergedZoneBrandingInformation.resolveBranding().getCompanyName();
            return StringUtils.hasText(companyName) ?
                    messageSource.getMessage("verify_email.subject.branded", new String[] { companyName }, locale) :
                    messageSource.getMessage("verify_email.subject", new String[] { companyName }, locale);
        }
        else {
            return messageSource.getMessage("verify_email.subject.branded", new String[] { IdentityZoneHolder.get().getName() }, locale);
        }
    }

    private String getEmailChangeEmailHtml(String email, String newEmail, String code, Locale locale) {
        String verifyUrl = UaaUrlUtils.getUaaUrl("/verify_email", IdentityZoneHolder.get());

        final Context ctx = new Context(locale);
        if (IdentityZoneHolder.isUaa()) {
            String companyName = MergedZoneBrandingInformation.resolveBranding().getCompanyName();
            ctx.setVariable("serviceName", StringUtils.hasText(companyName) ? companyName : "Cloud Foundry");
            ctx.setVariable("servicePhrase", StringUtils.hasText(companyName) ?
                    messageSource.getMessage("verify_email.request.service_phrase.branded", new String[] { companyName }, locale) :
                    messageSource.getMessage("verify_email.request.service_phrase", null, locale));
        }
        else {
            ctx.setVariable("serviceName", IdentityZoneHolder.get().getName());
            ctx.setVariable("servicePhrase",
                    messageSource.getMessage("verify_email.request.service_phrase.branded", new String[] { IdentityZoneHolder.get().getName() }, locale));
        }
        ctx.setVariable("code", code);
        ctx.setVariable("newEmail", newEmail);
        ctx.setVariable("email", email);
        ctx.setVariable("verifyUrl", verifyUrl);
        return templateEngine.process("verify_email", ctx);
    }

}
