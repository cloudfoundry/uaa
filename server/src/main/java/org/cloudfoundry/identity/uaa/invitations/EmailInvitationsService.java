package org.cloudfoundry.identity.uaa.invitations;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.INVITATION;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;

@Service
public class EmailInvitationsService implements InvitationsService {
    public static final String USER_ID = "user_id";
    public static final String EMAIL = "email";
    private final Log logger = LogFactory.getLog(getClass());


    @Autowired
    private ScimUserProvisioning scimUserProvisioning;

    @Autowired
    private ExpiringCodeStore expiringCodeStore;

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Override
    public AcceptedInvitation acceptInvitation(String code, String password) {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code);

        if ((null == expiringCode) || (null != expiringCode.getIntent() && !INVITATION.name().equals(expiringCode.getIntent()))) {
            throw new HttpClientErrorException(HttpStatus.BAD_REQUEST);
        }

        Map<String,String> userData = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
        String userId = userData.get(USER_ID);
        String clientId = userData.get(CLIENT_ID);
        String redirectUri = userData.get(REDIRECT_URI);

        ScimUser user = scimUserProvisioning.retrieve(userId);

        user = scimUserProvisioning.verifyUser(userId, user.getVersion());


        if (OriginKeys.UAA.equals(user.getOrigin()) && StringUtils.hasText(password)) {
            PasswordChangeRequest request = new PasswordChangeRequest();
            request.setPassword(password);
            scimUserProvisioning.changePassword(userId, null, password);
        }

        String redirectLocation = "/home";
        try {
            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
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
