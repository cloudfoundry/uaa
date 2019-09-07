package org.cloudfoundry.identity.uaa.invitations;

import com.fasterxml.jackson.core.type.TypeReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.INVITATION;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;

@Service
public class EmailInvitationsService implements InvitationsService {
    public static final String USER_ID = "user_id";
    public static final String EMAIL = "email";
    private final Logger logger = LoggerFactory.getLogger(getClass());


    @Autowired
    private ScimUserProvisioning scimUserProvisioning;

    @Autowired
    private ExpiringCodeStore expiringCodeStore;

    @Autowired
    private MultitenantClientServices clientDetailsService;

    @Override
    public AcceptedInvitation acceptInvitation(String code, String password) {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code, IdentityZoneHolder.get().getId());

        if ((null == expiringCode) || (null != expiringCode.getIntent() && !INVITATION.name().equals(expiringCode.getIntent()))) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST);
        }

        Map<String,String> userData = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
        String userId = userData.get(USER_ID);
        String clientId = userData.get(CLIENT_ID);
        String redirectUri = userData.get(REDIRECT_URI);

        ScimUser user = scimUserProvisioning.retrieve(userId, IdentityZoneHolder.get().getId());

        if (UAA.equals(user.getOrigin())) {
            user = scimUserProvisioning.verifyUser(userId, user.getVersion(), IdentityZoneHolder.get().getId());

            if (StringUtils.hasText(password)) {
                PasswordChangeRequest request = new PasswordChangeRequest();
                request.setPassword(password);
                scimUserProvisioning.changePassword(userId, null, password, IdentityZoneHolder.get().getId());
            }
        }

        String redirectLocation = "/home";
        try {
            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
            Set<String> redirectUris = clientDetails.getRegisteredRedirectUri();
            redirectLocation = UaaUrlUtils.findMatchingRedirectUri(redirectUris, redirectUri, redirectLocation);
        } catch (NoSuchClientException x) {
            logger.debug("Unable to find client_id for invitation:"+clientId);
        } catch (Exception x) {
            logger.error("Unable to resolve redirect for clientID:"+clientId, x);
        }
        return new AcceptedInvitation(redirectLocation, user);
    }
}
