package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.AccountCreationService.ExistingUserResponse;
import org.cloudfoundry.identity.uaa.message.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring4.SpringTemplateEngine;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class EmailInvitationsService implements InvitationsService {
    private final Log logger = LogFactory.getLog(getClass());

    public static final String INVITATION_REDIRECT_URL = "invitation_redirect_url";
    public static final int INVITATION_EXPIRY_DAYS = 365;

    private final SpringTemplateEngine templateEngine;
    private final MessageService messageService;
    private final String uaaBaseUrl;

    private String brand;

    public EmailInvitationsService(SpringTemplateEngine templateEngine, MessageService messageService, String brand, String uaaBaseUrl) {
        this.templateEngine = templateEngine;
        this.messageService = messageService;
        this.brand = brand;
        this.uaaBaseUrl = uaaBaseUrl;
    }

    public void setBrand(String brand) {
        this.brand = brand;
    }
    
    @Autowired
    private AccountCreationService accountCreationService;

    @Autowired
    private ExpiringCodeService expiringCodeService;

    @Autowired
    private RestTemplate authorizationTemplate;

    private void sendInvitationEmail(String email, String userId, String currentUser, String code) {
        String subject = getSubjectText();
        try {
            String htmlContent = getEmailHtml(currentUser, code);
                messageService.sendMessage(userId, email, MessageType.INVITATION, subject, htmlContent);
        } catch (RestClientException e) {
            logger.info("Exception raised while creating invitation email from " + email, e);
        }
    }

    private String getSubjectText() {
        return brand.equals("pivotal") ? "Invitation to join Pivotal" : "Invitation to join Cloud Foundry";
    }

    private String getEmailHtml(String currentUser, String code) {
        String accountsUrl = ServletUriComponentsBuilder.fromCurrentContextPath().path("/invitations/accept").build().toUriString();
        final Context ctx = new Context();
        ctx.setVariable("serviceName", brand.equals("pivotal") ? "Pivotal" : "Cloud Foundry");
        ctx.setVariable("code", code);
        ctx.setVariable("currentUser", currentUser);
        ctx.setVariable("accountsUrl", accountsUrl);
        return templateEngine.process("invite", ctx);
    }

    @Override
    public void inviteUser(String email, String currentUser) {
        try {
            ScimUser user = accountCreationService.createUser(email, null);
            Map<String,String> data = new HashMap<>();
            data.put("user_id", user.getId());
            data.put("email", email);
            String code = expiringCodeService.generateCode(data, INVITATION_EXPIRY_DAYS, TimeUnit.DAYS);
            sendInvitationEmail(email, user.getId(), currentUser, code);
        } catch (HttpClientErrorException e) {
            String uaaResponse = e.getResponseBodyAsString();
            try {
                ExistingUserResponse existingUserResponse = new ObjectMapper().readValue(uaaResponse, ExistingUserResponse.class);
                if (existingUserResponse.getVerified()) {
                    throw new UaaException(e.getStatusText(), e.getStatusCode().value());
                }
                Map<String,String> data = new HashMap<>();
                data.put("user_id", existingUserResponse.getUserId());
                data.put("email", email);
                String code = expiringCodeService.generateCode(data, INVITATION_EXPIRY_DAYS, TimeUnit.DAYS);
                sendInvitationEmail(email, existingUserResponse.getUserId(), currentUser, code);
            } catch (IOException ioe) {
            	logger.warn("couldn't invite user",ioe);
            }
        } catch (IOException e) {
            logger.warn("couldn't invite user",e);
        }
    }

    @Override
    public String acceptInvitation(String userId, String email, String password, String clientId) {
        authorizationTemplate.getForEntity(uaaBaseUrl + "/Users/" + userId + "/verify",Object.class);

        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setPassword(password);
        authorizationTemplate.put(uaaBaseUrl + "/Users/" + userId + "/password", request);

        String redirectLocation = null;
        if (clientId != null && !clientId.equals("")) {
            ClientDetails clientDetails = authorizationTemplate.getForObject(uaaBaseUrl + "/oauth/clients/" + clientId, BaseClientDetails.class);
            redirectLocation = (String) clientDetails.getAdditionalInformation().get(INVITATION_REDIRECT_URL);
        }

        return redirectLocation;
    }
}
