package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring4.SpringTemplateEngine;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.REGISTRATION;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.findMatchingRedirectUri;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class EmailAccountCreationService implements AccountCreationService {

    private final Log logger = LogFactory.getLog(getClass());

    public static final String SIGNUP_REDIRECT_URL = "signup_redirect_url";

    private final SpringTemplateEngine templateEngine;
    private final MessageService messageService;
    private final ExpiringCodeStore codeStore;
    private final ScimUserProvisioning scimUserProvisioning;
    private final ClientDetailsService clientDetailsService;
    private final PasswordValidator passwordValidator;

    public EmailAccountCreationService(
            SpringTemplateEngine templateEngine,
            MessageService messageService,
            ExpiringCodeStore codeStore,
            ScimUserProvisioning scimUserProvisioning,
            ClientDetailsService clientDetailsService,
            PasswordValidator passwordValidator) {

        this.templateEngine = templateEngine;
        this.messageService = messageService;
        this.codeStore= codeStore;
        this.scimUserProvisioning = scimUserProvisioning;
        this.clientDetailsService = clientDetailsService;
        this.passwordValidator = passwordValidator;
    }

    @Override
    public void beginActivation(String email, String password, String clientId, String redirectUri) {
        passwordValidator.validate(password);

        String subject = getSubjectText();
        try {
            ScimUser scimUser = createUser(email, password, OriginKeys.UAA);
            generateAndSendCode(email, clientId, subject, scimUser.getId(), redirectUri);
        } catch (ScimResourceAlreadyExistsException e) {
            List<ScimUser> users = scimUserProvisioning.query("userName eq \""+email+"\" and origin eq \""+ OriginKeys.UAA+"\"");
            try {
                if (users.size()>0) {
                    if (users.get(0).isVerified()) {
                        throw new UaaException("User already active.", HttpStatus.CONFLICT.value());
                    } else {
                        generateAndSendCode(email, clientId, subject, users.get(0).getId(), redirectUri);
                    }
                }

            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        } catch (IOException e) {
            logger.error("Exception raised while creating account activation email for " + email, e);
        }
    }

    private void generateAndSendCode(String email, String clientId, String subject, String userId, String redirectUri) throws IOException {
        ExpiringCode expiringCode = ScimUtils.getExpiringCode(codeStore, userId, email, clientId, redirectUri, REGISTRATION);
        String htmlContent = getEmailHtml(expiringCode.getCode(), email);

        messageService.sendMessage(email, MessageType.CREATE_ACCOUNT_CONFIRMATION, subject, htmlContent);
    }

    @Override
    public AccountCreationResponse completeActivation(String code) throws IOException {
        ExpiringCode expiringCode = codeStore.retrieveCode(code);
        if ((null == expiringCode) || ((null != expiringCode.getIntent()) && !REGISTRATION.name().equals(expiringCode.getIntent()))) {
            throw new HttpClientErrorException(BAD_REQUEST);
        }

        Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
        ScimUser user = scimUserProvisioning.retrieve(data.get("user_id"));
        user = scimUserProvisioning.verifyUser(user.getId(), user.getVersion());

        String clientId = data.get("client_id");
        String redirectUri = data.get("redirect_uri") != null ? data.get("redirect_uri") : "";
        String redirectLocation = getRedirect(clientId, redirectUri);

        return new AccountCreationResponse(user.getId(), user.getUserName(), user.getUserName(), redirectLocation);
    }

    private String getRedirect(String clientId, String redirectUri) throws IOException {
        if (clientId != null) {
            try {
                ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);

                Set<String> registeredRedirectUris = clientDetails.getRegisteredRedirectUri() == null ? Collections.emptySet() :
                        clientDetails.getRegisteredRedirectUri();
                String signupRedirectUrl = (String) clientDetails.getAdditionalInformation().get(SIGNUP_REDIRECT_URL);
                String matchingRedirectUri = findMatchingRedirectUri(registeredRedirectUris, redirectUri, signupRedirectUrl);

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
    public String getDefaultRedirect() throws IOException {
        return "home";
    }

    @Override
    public ScimUser createUser(String username, String password, String origin) {
        ScimUser scimUser = new ScimUser();
        scimUser.setUserName(username);
        ScimUser.Email email = new ScimUser.Email();
        email.setPrimary(true);
        email.setValue(username);
        scimUser.setEmails(Arrays.asList(email));
        scimUser.setOrigin(origin);
        scimUser.setPassword(password);
        scimUser.setVerified(false);
        try {
            ScimUser userResponse = scimUserProvisioning.createUser(scimUser, password);
            return userResponse;
        } catch (RuntimeException x) {
            if (x instanceof ScimResourceAlreadyExistsException) {
                throw x;
            }
            throw new UaaException("Couldn't create user:"+username, x);
        }
    }

    private String getSubjectText() {
        return StringUtils.hasText(IdentityZoneHolder.resolveBranding().getCompanyName()) && IdentityZoneHolder.isUaa() ?  "Activate your " + IdentityZoneHolder.resolveBranding().getCompanyName() + " account" : "Activate your account";
    }

    private String getEmailHtml(String code, String email) {
        String accountsUrl = ScimUtils.getVerificationURL(null).toString();

        final Context ctx = new Context();
        String companyName = IdentityZoneHolder.resolveBranding().getCompanyName();
        if (IdentityZoneHolder.isUaa()) {
            ctx.setVariable("serviceName", StringUtils.hasText(companyName) ? companyName : "Cloud Foundry");
        } else {
            ctx.setVariable("serviceName", IdentityZoneHolder.get().getName());
        }
        ctx.setVariable("servicePhrase", StringUtils.hasText(companyName) && IdentityZoneHolder.isUaa() ? companyName + " account" : "an account");
        ctx.setVariable("code", code);
        ctx.setVariable("email", email);
        ctx.setVariable("accountsUrl", accountsUrl);
        return templateEngine.process("activate", ctx);
    }
}
