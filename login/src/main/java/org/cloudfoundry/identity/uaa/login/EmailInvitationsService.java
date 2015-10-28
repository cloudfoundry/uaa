package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.invitations.InvitationsService;
import org.cloudfoundry.identity.uaa.message.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring4.SpringTemplateEngine;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.authentication.Origin.ORIGIN;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;

@Service
public class EmailInvitationsService implements InvitationsService {
    public static final String USER_ID = "user_id";
    public static final String EMAIL = "email";
    private final Log logger = LogFactory.getLog(getClass());

    public static final int INVITATION_EXPIRY_DAYS = 7;

    private final SpringTemplateEngine templateEngine;
    private final MessageService messageService;

    @Autowired
    private ScimUserProvisioning scimUserProvisioning;
    private String brand;

    public EmailInvitationsService(SpringTemplateEngine templateEngine, MessageService messageService, String brand) {
        this.templateEngine = templateEngine;
        this.messageService = messageService;
        this.brand = brand;
    }

    public void setBrand(String brand) {
        this.brand = brand;
    }

    @Autowired
    private ExpiringCodeStore expiringCodeStore;

    @Autowired
    private ClientDetailsService clientDetailsService;

    private void sendInvitationEmail(String email, String currentUser, String code) {
        String subject = getSubjectText();
        try {
            String htmlContent = getEmailHtml(currentUser, code);
            messageService.sendMessage(email, MessageType.INVITATION, subject, htmlContent);
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
    public AcceptedInvitation acceptInvitation(String code, String password) {
        ExpiringCode data = expiringCodeStore.retrieveCode(code);

        Map<String,String> userData = JsonUtils.readValue(data.getData(), new TypeReference<Map<String, String>>() {});
        String userId = userData.get(USER_ID);
        String clientId = userData.get(CLIENT_ID);
        String redirectUri = userData.get(REDIRECT_URI);

        ScimUser user = scimUserProvisioning.retrieve(userId);

        user = scimUserProvisioning.verifyUser(userId, user.getVersion());
        if (Origin.UAA.equals(user.getOrigin())) {
            PasswordChangeRequest request = new PasswordChangeRequest();
            request.setPassword(password);
            scimUserProvisioning.changePassword(userId, null, password);
        }
        String redirectLocation = "/home";
        try {
            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
            Set<String> redirectUris = clientDetails.getRegisteredRedirectUri();
            String matchingRedirectUri = UaaUrlUtils.findMatchingRedirectUri(redirectUris, redirectUri);
            if (StringUtils.hasText(matchingRedirectUri)) {
                redirectLocation = redirectUri;
            }
        } catch (NoSuchClientException x) {
            logger.debug("Unable to find client_id for invitation:"+clientId);
        } catch (Exception x) {
            logger.error("Unable to resolve redirect for clientID:"+clientId, x);
        }
        return new AcceptedInvitation(redirectLocation, user);
    }
}
