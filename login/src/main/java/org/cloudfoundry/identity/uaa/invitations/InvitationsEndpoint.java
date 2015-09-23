package org.cloudfoundry.identity.uaa.invitations;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.invitations.InvitationsResponse.InvitedUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConflictException;
import org.cloudfoundry.identity.uaa.util.DomainFilter;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;

@Controller
public class InvitationsEndpoint {

    private InvitationsService invitationsService;
    private ScimUserProvisioning users;
    private IdentityProviderProvisioning providers;
    private ClientDetailsService clients;

    public InvitationsEndpoint(InvitationsService invitationsService,
                               ScimUserProvisioning users,
                               IdentityProviderProvisioning providers,
                               ClientDetailsService clients) {
        this.invitationsService = invitationsService;
        this.users = users;
        this.providers = providers;
        this.clients = clients;
    }

    @RequestMapping(value="/invite_users", method= RequestMethod.POST, consumes="application/json")
    public ResponseEntity<InvitationsResponse> inviteUsers(@RequestBody InvitationsRequest invitations, @RequestParam(value="client_id") String clientId, @RequestParam(value="redirect_uri") String redirectUri) {

        // todo: get clientId from token, if not supplied in clientId

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUser = null;
        if (authentication instanceof OAuth2Authentication) {
            OAuth2Authentication oAuth2Authentication = (OAuth2Authentication)authentication;
            if (!oAuth2Authentication.isClientOnly()) {
                currentUser = ((UaaPrincipal) oAuth2Authentication.getPrincipal()).getName();
            } else {
                currentUser = oAuth2Authentication.getOAuth2Request().getClientId();
            }

            if (clientId==null) {
                clientId = oAuth2Authentication.getOAuth2Request().getClientId();
            }
        }

        InvitationsResponse invitationsResponse = new InvitationsResponse();
        List<String> newInvitesEmails = new ArrayList<>();

        DomainFilter filter = new DomainFilter();
        List<IdentityProvider> activeProviders = providers.retrieveActive(IdentityZoneHolder.get().getId());
        ClientDetails client = clients.loadClientByClientId(clientId);
         for (String email : invitations.getEmails()) {
            try {
                List<IdentityProvider> providers = filter.filter(activeProviders, client, email);
                if (providers.size()==1) {
                    ScimUser user = findOrCreateUser(email, providers.get(0).getOriginKey());
                    invitationsService.inviteUser(user, currentUser, clientId, redirectUri);
                    invitationsResponse.getNewInvites().add(InvitationsResponse.success(user.getPrimaryEmail(), user.getId(), user.getOrigin()));
                } else if (providers.size()==0) {
                    invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "provider.non-existent", "No authentication provider found."));
                } else {
                    invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "provider.ambiguous", "Multiple authentication providers found."));
                }
            } catch (UaaException uaae) {
                invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "invitation.exception", uaae.getMessage()));
            }
        }
        return new ResponseEntity<>(invitationsResponse, HttpStatus.OK);
    }

    protected ScimUser findOrCreateUser(String email, String origin) {
        email = email.trim().toLowerCase();
        List<ScimUser> results = users.query(String.format("email eq \"%s\" and origin eq \"%s\"", email, origin));
        if (results==null || results.size()==0) {
            ScimUser user = new ScimUser(null, email, "", "");
            user.setPrimaryEmail(email.toLowerCase());
            user.setOrigin(origin);
            user.setVerified(false);
            user.setActive(true);
            return users.createUser(user, new RandomValueStringGenerator(12).generate());
        } else if (results.size()==1) {
            return results.get(0);
        } else {
            throw new ScimResourceConflictException(String.format("Ambiguous users found for email:%s with origin:%s", email, origin));
        }
    }

}
