package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.util.ScimUtils;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MergedZoneBrandingInformation;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.REGISTRATION;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.findMatchingRedirectUri;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Service
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

    public EmailAccountCreationService(
            @Qualifier("mailTemplateEngine") SpringTemplateEngine templateEngine,
            MessageService messageService,
            ExpiringCodeStore codeStore,
            ScimUserProvisioning scimUserProvisioning,
            MultitenantClientServices clientDetailsService,
            PasswordValidator passwordValidator,
            IdentityZoneManager identityZoneManager) {

        this.templateEngine = templateEngine;
        this.messageService = messageService;
        this.codeStore = codeStore;
        this.scimUserProvisioning = scimUserProvisioning;
        this.clientDetailsService = clientDetailsService;
        this.passwordValidator = passwordValidator;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    public void beginActivation(String email, String password, String clientId, String redirectUri) {
        passwordValidator.validate(password);

        String subject = buildSubjectText();
        try {
            ScimUser scimUser = createUser(email, password, OriginKeys.UAA);
            generateAndSendCode(email, clientId, subject, scimUser.getId(), redirectUri, identityZoneManager.getCurrentIdentityZone());
        } catch (ScimResourceAlreadyExistsException e) {
            List<ScimUser> users = scimUserProvisioning.retrieveByUsernameAndOriginAndZone(email, OriginKeys.UAA, identityZoneManager.getCurrentIdentityZoneId());
            if (!users.isEmpty()) {
                if (users.getFirst().isVerified()) {
                    throw new UaaException("User already active.", HttpStatus.CONFLICT.value());
                } else {
                    generateAndSendCode(email, clientId, subject, users.getFirst().getId(), redirectUri, identityZoneManager.getCurrentIdentityZone());
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
            IdentityZone currentIdentityZone) {
        ExpiringCode expiringCode = ScimUtils.getExpiringCode(
                codeStore,
                userId,
                email,
                clientId,
                redirectUri,
                REGISTRATION,
                identityZoneManager.getCurrentIdentityZoneId());
        String htmlContent = getEmailHtml(expiringCode.getCode(), email, currentIdentityZone);

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
                logger.debug("Unable to find client with ID:%s for account activation redirect".formatted(clientId), nsce);
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

    private String buildSubjectText() {
        String companyName = MergedZoneBrandingInformation.resolveBranding().getCompanyName();
        boolean addBranding = StringUtils.hasText(companyName) && identityZoneManager.isCurrentZoneUaa();
        if (addBranding) {
            return "Activate your %s account".formatted(companyName);
        } else {
            return "Activate your account";
        }
    }

    private String getEmailHtml(String code, String email, IdentityZone currentIdentityZone) {
        String accountsUrl = ScimUtils.getVerificationURL(null, currentIdentityZone).toString();

        final Context ctx = new Context();
        String companyName = MergedZoneBrandingInformation.resolveBranding().getCompanyName();
        if (currentIdentityZone.isUaa()) {
            ctx.setVariable("serviceName", StringUtils.hasText(companyName) ? companyName : "Cloud Foundry");
        } else {
            ctx.setVariable("serviceName", currentIdentityZone.getName());
        }
        ctx.setVariable("servicePhrase", StringUtils.hasText(companyName) && currentIdentityZone.isUaa() ? companyName + " account" : "an account");
        ctx.setVariable("code", code);
        ctx.setVariable("email", email);
        ctx.setVariable("accountsUrl", accountsUrl);
        return templateEngine.process("activate", ctx);
    }
}
