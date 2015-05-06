package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.web.client.HttpClientErrorException;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring4.SpringTemplateEngine;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EmailAccountCreationService implements AccountCreationService {

    public static final String SIGNUP_REDIRECT_URL = "signup_redirect_url";

    private final Log logger = LogFactory.getLog(getClass());

    private final SpringTemplateEngine templateEngine;
    private final MessageService messageService;
    private final ExpiringCodeStore codeStore;
    private final ScimUserProvisioning scimUserProvisioning;
    private final ClientDetailsService clientDetailsService;
    private final String brand;
    private final UaaUrlUtils uaaUrlUtils;

    public EmailAccountCreationService(
        SpringTemplateEngine templateEngine,
        MessageService messageService,
        ExpiringCodeStore codeStore,
        ScimUserProvisioning scimUserProvisioning,
        ClientDetailsService clientDetailsService,
        UaaUrlUtils uaaUrlUtils,
        String brand) {

        this.templateEngine = templateEngine;
        this.messageService = messageService;
        this.codeStore= codeStore;
        this.scimUserProvisioning = scimUserProvisioning;
        this.clientDetailsService = clientDetailsService;
        this.uaaUrlUtils = uaaUrlUtils;
        this.brand = brand;
    }

    @Override
    public void beginActivation(String email, String password, String clientId) {

        String subject = getSubjectText();
        try {
            ScimUser scimUser = createUser(email, password);
            generateAndSendCode(email, clientId, subject, scimUser.getId());
        } catch (ScimResourceAlreadyExistsException e) {
            List<ScimUser> users = scimUserProvisioning.query("userName eq \""+email+"\" and origin eq \""+Origin.UAA+"\"");
            try {
                if (users.size()>0) {
                    if (users.get(0).isVerified()) {
                        throw new UaaException("User already active.", HttpStatus.CONFLICT.value());
                    } else {
                        generateAndSendCode(email, clientId, subject, users.get(0).getId());
                    }
                }

            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        } catch (IOException e) {
            logger.error("Exception raised while creating account activation email for " + email, e);
        }
    }

    private void generateAndSendCode(String email, String clientId, String subject, String userId) throws IOException {
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + (60 * 60 * 1000)); // 1 hour
        ExpiringCode expiringCodeForPost = getExpiringCode(userId, clientId, expiresAt);
        ExpiringCode expiringCode = codeStore.generateCode(expiringCodeForPost.getData(), expiringCodeForPost.getExpiresAt());
        String htmlContent = getEmailHtml(expiringCode.getCode(), email);

        messageService.sendMessage(userId, email, MessageType.CREATE_ACCOUNT_CONFIRMATION, subject, htmlContent);
    }

    private ExpiringCode getExpiringCode(String userId, String clientId, Timestamp expiresAt) throws IOException {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", userId);
        codeData.put("client_id", clientId);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        return new ExpiringCode(null, expiresAt, codeDataString);
    }

    @Override
    public AccountCreationResponse completeActivation(String code) throws IOException {

        ExpiringCode expiringCode = codeStore.retrieveCode(code);
        if (expiringCode==null) {
            //just to satisfy unit tests
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST);
        }

        Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
        ScimUser user = scimUserProvisioning.retrieve(data.get("user_id"));
        user = scimUserProvisioning.verifyUser(user.getId(), user.getVersion());

        String clientId = data.get("client_id");
        String redirectLocation;
        if (clientId != null) {
            try {
                ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
                redirectLocation = (String) clientDetails.getAdditionalInformation().get(SIGNUP_REDIRECT_URL);
            }
            catch (NoSuchClientException e) {
                redirectLocation = getDefaultRedirect();
            }
        } else {
            redirectLocation = getDefaultRedirect();
        }

        return new AccountCreationResponse(user.getId(), user.getUserName(), user.getUserName(), redirectLocation);
    }

    private String getDefaultRedirect() throws IOException {
        return "home";
    }

    @Override
    public void resendVerificationCode(String email, String clientId) {
        List<ScimUser> resources = scimUserProvisioning.query("userName eq \"" + email + "\" and origin eq \"" + Origin.UAA + "\"");
        String userId = resources.get(0).getId();
        try {
            generateAndSendCode(email, clientId, getSubjectText(), userId);
        } catch (IOException e) {
            logger.error("Exception raised while resending activation email for " + email, e);
        }
    }

    @Override
    public ScimUser createUser(String username, String password) {
        ScimUser scimUser = new ScimUser();
        scimUser.setUserName(username);
        ScimUser.Email email = new ScimUser.Email();
        email.setPrimary(true);
        email.setValue(username);
        scimUser.setEmails(Arrays.asList(email));
        scimUser.setOrigin(Origin.UAA);
        scimUser.setPassword(password);
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
        return brand.equals("pivotal") ? "Activate your Pivotal ID" : "Activate your account";
    }

    private String getEmailHtml(String code, String email) {
        String accountsUrl = uaaUrlUtils.getUaaUrl("/verify_user");

        final Context ctx = new Context();
        if (IdentityZoneHolder.get().equals(IdentityZone.getUaa())) {
            ctx.setVariable("serviceName", brand.equals("pivotal") ? "Pivotal" : "Cloud Foundry");
        } else {
            ctx.setVariable("serviceName", IdentityZoneHolder.get().getName());
        }
        ctx.setVariable("servicePhrase", brand.equals("pivotal") ? "a Pivotal ID" : "an account");
        ctx.setVariable("code", code);
        ctx.setVariable("email", email);
        ctx.setVariable("accountsUrl", accountsUrl);
        return templateEngine.process("activate", ctx);
    }
}
