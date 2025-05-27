package org.cloudfoundry.identity.uaa.invitations;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.INVITATION;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.REDIRECT_URI;

@Service
public class EmailInvitationsService implements InvitationsService {
    public static final String USER_ID = "user_id";
    public static final String EMAIL = "email";
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private final MultitenantClientServices clientDetailsService;
    private final IdentityZoneManager identityZoneManager;

    public EmailInvitationsService(
            final ScimUserProvisioning scimUserProvisioning,
            final ExpiringCodeStore expiringCodeStore,
            final MultitenantClientServices clientDetailsService,
            final IdentityZoneManager identityZoneManager) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
        this.clientDetailsService = clientDetailsService;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    public AcceptedInvitation acceptInvitation(String code, String password) {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code, identityZoneManager.getCurrentIdentityZoneId());

        if ((null == expiringCode) || (null != expiringCode.getIntent() && !INVITATION.name().equals(expiringCode.getIntent()))) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST);
        }

        Map<String, String> userData = JsonUtils.readValue(expiringCode.getData(), new TypeReference<>() {
        });
        String userId = userData.get(USER_ID);
        String clientId = userData.get(CLIENT_ID);
        String redirectUri = userData.get(REDIRECT_URI);

        ScimUser user = scimUserProvisioning.retrieve(userId, identityZoneManager.getCurrentIdentityZoneId());

        if (UAA.equals(user.getOrigin())) {
            user = scimUserProvisioning.verifyUser(userId, user.getVersion(), identityZoneManager.getCurrentIdentityZoneId());

            if (StringUtils.hasText(password)) {
                PasswordChangeRequest request = new PasswordChangeRequest();
                request.setPassword(password);
                scimUserProvisioning.changePassword(userId, null, password, identityZoneManager.getCurrentIdentityZoneId());
            }
        }

        String redirectLocation = "/home";
        try {
            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());
            Set<String> redirectUris = clientDetails.getRegisteredRedirectUri();
            redirectLocation = UaaUrlUtils.findMatchingRedirectUri(redirectUris, redirectUri, redirectLocation);
        } catch (NoSuchClientException x) {
            logger.debug("Unable to find client_id for invitation:{}", clientId);
        } catch (Exception x) {
            logger.error("Unable to resolve redirect for clientID:{}", clientId, x);
        }
        return new AcceptedInvitation(redirectLocation, user);
    }
}
