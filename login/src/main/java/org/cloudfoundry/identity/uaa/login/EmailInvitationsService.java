package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.AccountCreationService.ExistingUserResponse;
import org.cloudfoundry.identity.uaa.message.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring4.SpringTemplateEngine;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Service
public class EmailInvitationsService implements InvitationsService {
    private final Log logger = LogFactory.getLog(getClass());

    public static final int INVITATION_EXPIRY_DAYS = 365;

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
    private AccountCreationService accountCreationService;

    @Autowired
    private ExpiringCodeService expiringCodeService;

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
    public void inviteUser(String email, String currentUser, String clientId, String redirectUri) {
        try {
            ScimUser user = accountCreationService.createUser(email, new RandomValueStringGenerator().generate(), Origin.UNKNOWN);
            Map<String,String> data = new HashMap<>();
            data.put("user_id", user.getId());
            data.put("email", email);
            data.put("client_id", clientId);
            data.put("redirect_uri", redirectUri);
            String code = expiringCodeService.generateCode(data, INVITATION_EXPIRY_DAYS, TimeUnit.DAYS);
            sendInvitationEmail(email, currentUser, code);
        } catch (ScimResourceAlreadyExistsException e) {
            try {
                ExistingUserResponse existingUserResponse = JsonUtils.convertValue(e.getExtraInfo(), ExistingUserResponse.class);
                if (existingUserResponse.getVerified()) {
                    throw new UaaException(e.getMessage(), e.getStatus().value());
                }
                Map<String,String> data = new HashMap<>();
                data.put("user_id", existingUserResponse.getUserId());
                data.put("email", email);
                data.put("client_id", clientId);
                data.put("redirect_uri", redirectUri);
                String code = expiringCodeService.generateCode(data, INVITATION_EXPIRY_DAYS, TimeUnit.DAYS);
                sendInvitationEmail(email, currentUser, code);
            } catch (JsonUtils.JsonUtilException ioe) {
                logger.warn("couldn't invite user",ioe);
            } catch (IOException ioe) {
                logger.warn("couldn't invite user",ioe);
            }
        } catch (IOException e) {
            logger.warn("couldn't invite user",e);
        }
    }

    @Override
    public AcceptedInvitation acceptInvitation(String userId, String email, String password, String clientId, String redirectUri, String origin) {
        ScimUser user = getScimUserFromInvitation(userId, email, origin);
        //in case we got an existing user
        userId = user.getId();
        user = scimUserProvisioning.verifyUser(userId, user.getVersion());
        if (!user.getOrigin().equals(origin)) {
            user.setOrigin(origin);
            user = scimUserProvisioning.update(userId, user);
        }
        if (Origin.UAA.equals(user.getOrigin())) {
            PasswordChangeRequest request = new PasswordChangeRequest();
            request.setPassword(password);
            scimUserProvisioning.changePassword(userId, null, password);
        }
        String redirectLocation = "/home";
        if (!clientId.equals("")) {
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
        }
        return new AcceptedInvitation(redirectLocation, user);
    }

    protected ScimUser getScimUserFromInvitation(String userId, String username, String origin) {
        if (Origin.UAA.equals(origin)) {
            List<ScimUser> results = scimUserProvisioning.query(String.format("username eq \"%s\" and origin eq \"%s\"", username, Origin.UAA));
            if (results != null && results.size() == 1) {
                return results.get(0);
            }
        }
        return scimUserProvisioning.retrieve(userId);
    }
}
