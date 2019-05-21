package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.core.type.TypeReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.util.ScimUtils;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MergedZoneBrandingInformation;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring4.SpringTemplateEngine;

import java.util.*;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.REGISTRATION;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.findMatchingRedirectUri;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class EmailAccountCreationService implements AccountCreationService {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    public static final String SIGNUP_REDIRECT_URL = "signup_redirect_url";

    private final SpringTemplateEngine templateEngine;
    private final MessageService messageService;
    private final ExpiringCodeStore codeStore;
    private final ScimUserProvisioning scimUserProvisioning;
    private final MultitenantClientServices clientDetailsService;
    private final PasswordValidator passwordValidator;
    private final IdentityZoneManager identityZoneManager;
    private final MessageSource messageSource;

    public EmailAccountCreationService(
            SpringTemplateEngine templateEngine,
            MessageService messageService,
            ExpiringCodeStore codeStore,
            ScimUserProvisioning scimUserProvisioning,
            MultitenantClientServices clientDetailsService,
            PasswordValidator passwordValidator,
            IdentityZoneManager identityZoneManager,
            MessageSource messageSource) {

        this.templateEngine = templateEngine;
        this.messageService = messageService;
        this.codeStore = codeStore;
        this.scimUserProvisioning = scimUserProvisioning;
        this.clientDetailsService = clientDetailsService;
        this.passwordValidator = passwordValidator;
        this.identityZoneManager = identityZoneManager;
        this.messageSource = messageSource;
    }

    @Override
    public void beginActivation(String email, String password, String clientId, String redirectUri, Locale locale) {
        passwordValidator.validate(password);

        String subject = buildSubjectText(locale);
        try {
            ScimUser scimUser = createUser(email, password, OriginKeys.UAA);
            generateAndSendCode(email, clientId, subject, scimUser.getId(), redirectUri, identityZoneManager.getCurrentIdentityZone(), locale);
        } catch (ScimResourceAlreadyExistsException e) {
            List<ScimUser> users = scimUserProvisioning.query("userName eq \"" + email + "\" and origin eq \"" + OriginKeys.UAA + "\"", identityZoneManager.getCurrentIdentityZoneId());
            if (users.size() > 0) {
                if (users.get(0).isVerified()) {
                    throw new UaaException("User already active.", HttpStatus.CONFLICT.value());
                } else {
                    generateAndSendCode(email, clientId, subject, users.get(0).getId(), redirectUri, identityZoneManager.getCurrentIdentityZone(),
                            locale);
                }
            }
        }
    }

    private void generateAndSendCode(
            String email,
            String clientId,
            String subject,
            String userId,
            String redirectUri,
            IdentityZone currentIdentityZone,
            Locale locale) {
        ExpiringCode expiringCode = ScimUtils.getExpiringCode(
                codeStore,
                userId,
                email,
                clientId,
                redirectUri,
                REGISTRATION,
                identityZoneManager.getCurrentIdentityZoneId());
        String htmlContent = getEmailHtml(expiringCode.getCode(), email, currentIdentityZone, locale);

        messageService.sendMessage(email, MessageType.CREATE_ACCOUNT_CONFIRMATION, subject, htmlContent);
    }

    @Override
    public AccountCreationResponse completeActivation(String code) {
        ExpiringCode expiringCode = codeStore.retrieveCode(code, identityZoneManager.getCurrentIdentityZoneId());
        if ((null == expiringCode) || ((null != expiringCode.getIntent()) && !REGISTRATION.name().equals(expiringCode.getIntent()))) {
            throw new HttpClientErrorException(BAD_REQUEST);
        }

        Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {
        });
        ScimUser user = scimUserProvisioning.retrieve(data.get("user_id"), identityZoneManager.getCurrentIdentityZoneId());
        user = scimUserProvisioning.verifyUser(user.getId(), user.getVersion(), identityZoneManager.getCurrentIdentityZoneId());

        String clientId = data.get("client_id");
        String redirectUri = data.get("redirect_uri") != null ? data.get("redirect_uri") : "";
        String redirectLocation = getRedirect(clientId, redirectUri);

        return new AccountCreationResponse(user.getId(), user.getUserName(), user.getUserName(), redirectLocation);
    }

    private String getRedirect(String clientId, String redirectUri) {
        if (clientId != null) {
            try {
                ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());

                Set<String> registeredRedirectUris = clientDetails.getRegisteredRedirectUri() == null ? Collections.emptySet() :
                        clientDetails.getRegisteredRedirectUri();
                String signupRedirectUrl = (String) clientDetails.getAdditionalInformation().get(SIGNUP_REDIRECT_URL);
                String matchingRedirectUri = findMatchingRedirectUri(registeredRedirectUris, redirectUri, Optional.ofNullable(signupRedirectUrl).orElse("home"));

                if (matchingRedirectUri != null) {
                    return matchingRedirectUri;
                }
            } catch (NoSuchClientException nsce) {
                logger.debug(String.format("Unable to find client with ID:%s for account activation redirect", clientId), nsce);
            }
        }

        return getDefaultRedirect();
    }

    @Override
    public String getDefaultRedirect() {
        return "home";
    }

    @Override
    public ScimUser createUser(String username, String password, String origin) {
        ScimUser scimUser = new ScimUser();
        scimUser.setUserName(username);
        ScimUser.Email email = new ScimUser.Email();
        email.setPrimary(true);
        email.setValue(username);
        scimUser.setEmails(Collections.singletonList(email));
        scimUser.setOrigin(origin);
        scimUser.setPassword(password);
        scimUser.setVerified(false);
        try {
            return scimUserProvisioning.createUser(scimUser, password, identityZoneManager.getCurrentIdentityZoneId());
        } catch (RuntimeException x) {
            if (x instanceof ScimResourceAlreadyExistsException) {
                throw x;
            }
            throw new UaaException("Couldn't create user:" + username, x);
        }
    }

    private String buildSubjectText(Locale locale) {
        String companyName = MergedZoneBrandingInformation.resolveBranding().getCompanyName();
        boolean addBranding = StringUtils.hasText(companyName) && identityZoneManager.isCurrentZoneUaa();
        if (addBranding) {
            return messageSource.getMessage("activate.subject.branded", new String[] { companyName }, locale);
        } else {
            return messageSource.getMessage("activate.subject", null, locale);
        }
    }

    private String getEmailHtml(String code, String email, IdentityZone currentIdentityZone, Locale locale) {
        String accountsUrl = ScimUtils.getVerificationURL(null, currentIdentityZone).toString();

        final Context ctx = new Context(locale);
        String companyName = MergedZoneBrandingInformation.resolveBranding().getCompanyName();
        if (currentIdentityZone.isUaa()) {
            ctx.setVariable("serviceName", StringUtils.hasText(companyName) ? companyName : "Cloud Foundry");
        } else {
            ctx.setVariable("serviceName", currentIdentityZone.getName());
        }
        ctx.setVariable("servicePhrase", StringUtils.hasText(companyName) && currentIdentityZone.isUaa() ?
                messageSource.getMessage("activate.request.service_phrase.branded", new String[] { companyName }, locale) :
                messageSource.getMessage("activate.request.service_phrase", null, locale));
        ctx.setVariable("code", code);
        ctx.setVariable("email", email);
        ctx.setVariable("accountsUrl", accountsUrl);
        return templateEngine.process("activate", ctx);
    }
}
