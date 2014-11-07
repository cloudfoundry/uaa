package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring4.SpringTemplateEngine;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EmailAccountCreationService implements AccountCreationService {

    public static final String SIGNUP_REDIRECT_URL = "signup_redirect_url";

    private final Log logger = LogFactory.getLog(getClass());

    private final SpringTemplateEngine templateEngine;
    private final MessageService messageService;
    private final RestTemplate uaaTemplate;
    private final String uaaBaseUrl;
    private final String brand;
    private final ObjectMapper objectMapper;
    private final String baseUrl;

    public EmailAccountCreationService(ObjectMapper objectMapper, SpringTemplateEngine templateEngine, MessageService messageService, RestTemplate uaaTemplate, String uaaBaseUrl, String brand, String baseUrl) {
        this.objectMapper = objectMapper;
        this.templateEngine = templateEngine;
        this.messageService = messageService;
        this.uaaTemplate = uaaTemplate;
        this.uaaBaseUrl = uaaBaseUrl;
        this.brand = brand;
        this.baseUrl = baseUrl;
    }

    @Override
    public void beginActivation(String email, String password, String clientId) {

        String subject = getSubjectText();
        try {
            ScimUser scimUser = createUser(email, password);
            generateAndSendCode(email, clientId, subject, scimUser.getId());
        } catch (HttpClientErrorException e) {
            String uaaResponse = e.getResponseBodyAsString();
            try {
                ExistingUserResponse existingUserResponse = new ObjectMapper().readValue(uaaResponse, ExistingUserResponse.class);
                if (existingUserResponse.getVerified()) {
                    throw new UaaException(e.getStatusText(), e.getStatusCode().value());
                }
                generateAndSendCode(email, clientId, subject, existingUserResponse.getUserId());
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        } catch (RestClientException e) {
            logger.error("Exception raised while creating account activation email for " + email, e);
        } catch (IOException e) {
            logger.error("Exception raised while creating account activation email for " + email, e);
        }
    }

    private void generateAndSendCode(String email, String clientId, String subject, String userId) throws IOException {
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + (60 * 60 * 1000)); // 1 hour
        ExpiringCode expiringCodeForPost = getExpiringCode(userId, clientId, expiresAt);
        ExpiringCode expiringCode = uaaTemplate.postForObject(uaaBaseUrl + "/Codes", expiringCodeForPost, ExpiringCode.class);
        String htmlContent = getEmailHtml(expiringCode.getCode(), email);

        messageService.sendMessage(userId, email, MessageType.CREATE_ACCOUNT_CONFIRMATION, subject, htmlContent);
    }

    private ExpiringCode getExpiringCode(String userId, String clientId, Timestamp expiresAt) throws IOException {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", userId);
        codeData.put("client_id", clientId);
        String codeDataString = objectMapper.writeValueAsString(codeData);
        return new ExpiringCode(null, expiresAt, codeDataString);
    }

    @Override
    public AccountCreationResponse completeActivation(String code) throws IOException {

        ExpiringCode expiringCode = uaaTemplate.getForObject(uaaBaseUrl + "/Codes/"+ code, ExpiringCode.class);
        Map<String, String> data = objectMapper.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
        ScimUser user = uaaTemplate.getForObject(uaaBaseUrl + "/Users/" + data.get("user_id") + "/verify", ScimUser.class);

        ClientDetails clientDetails = uaaTemplate.getForObject(uaaBaseUrl + "/oauth/clients/" + data.get("client_id"), BaseClientDetails.class);
        String redirectLocation = (String) clientDetails.getAdditionalInformation().get(SIGNUP_REDIRECT_URL);

        return new AccountCreationResponse(user.getId(), user.getUserName(), user.getUserName(), redirectLocation);
    }

    @Override
    public void resendVerificationCode(String email, String clientId) {
        String url = uaaBaseUrl + "/ids/Users?attributes=id&filter=userName eq \"" + email + "\" and origin eq \"" + Origin.UAA + "\"";
        Map<String,Object> response = uaaTemplate.getForObject(url, Map.class);
        List<Map<String,String>> resources = (ArrayList)response.get("resources");
        String userId = resources.get(0).get("id");

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
        ScimUser userResponse = uaaTemplate.postForObject(uaaBaseUrl + "/Users", scimUser, ScimUser.class);
        return userResponse;
    }
    
    private String getSubjectText() {
        return brand.equals("pivotal") ? "Activate your Pivotal ID" : "Activate your account";
    }

    private String getEmailHtml(String code, String email) {
        String accountsUrl = baseUrl + "/verify_user";

        final Context ctx = new Context();
        ctx.setVariable("serviceName", brand.equals("pivotal") ? "Pivotal" : "Cloud Foundry");
        ctx.setVariable("servicePhrase", brand.equals("pivotal") ? "a Pivotal ID" : "an account");
        ctx.setVariable("code", code);
        ctx.setVariable("email", email);
        ctx.setVariable("accountsUrl", accountsUrl);
        return templateEngine.process("activate", ctx);
    }
}
