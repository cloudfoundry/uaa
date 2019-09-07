package org.cloudfoundry.identity.uaa.invitations;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConflictException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.INVITATION;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.ORIGIN;
import static org.cloudfoundry.identity.uaa.util.DomainFilter.filter;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.HEADER;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.util.StringUtils.hasText;

@Controller
public class InvitationsEndpoint {

    public static final int INVITATION_EXPIRY_DAYS = 7;

    private ScimUserProvisioning users;
    private IdentityProviderProvisioning providers;
    private MultitenantClientServices clients;
    private ExpiringCodeStore expiringCodeStore;
    private Pattern emailPattern = Pattern.compile("^(.+)@(.+)\\.(.+)$");

    public InvitationsEndpoint(ScimUserProvisioning users,
                               IdentityProviderProvisioning providers,
                               MultitenantClientServices clients,
                               ExpiringCodeStore expiringCodeStore) {
        this.users = users;
        this.providers = providers;
        this.clients = clients;
        this.expiringCodeStore = expiringCodeStore;
    }

    @RequestMapping(value = "/invite_users", method = RequestMethod.POST, consumes = "application/json")
    public ResponseEntity<InvitationsResponse> inviteUsers(@RequestBody InvitationsRequest invitations,
                                                           @RequestParam(value = "client_id", required = false) String clientId,
                                                           @RequestParam(value = "redirect_uri") String redirectUri) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof OAuth2Authentication) {
            OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;

            if (clientId == null) {
                clientId = oAuth2Authentication.getOAuth2Request().getClientId();
            }
        }

        InvitationsResponse invitationsResponse = new InvitationsResponse();

        List<IdentityProvider> activeProviders = providers.retrieveActive(IdentityZoneHolder.get().getId());

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        String subdomainHeader = request.getHeader(SUBDOMAIN_HEADER);
        String zoneIdHeader = request.getHeader(HEADER);

        ClientDetails client = null;

        if (!hasText(subdomainHeader) && !hasText(zoneIdHeader)) {
            client = clients.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        }

        for (String email : invitations.getEmails()) {
            try {
                if (email!=null && emailPattern.matcher(email).matches()) {
                    List<IdentityProvider> providers = filter(activeProviders, client, email);
                    if (providers.size() == 1) {
                        ScimUser user = findOrCreateUser(email, providers.get(0).getOriginKey());
                        String accountsUrl = UaaUrlUtils.getUaaUrl("/invitations/accept", !IdentityZoneHolder.isUaa(), IdentityZoneHolder.get());

                        Map<String, String> data = new HashMap<>();
                        data.put(InvitationConstants.USER_ID, user.getId());
                        data.put(InvitationConstants.EMAIL, user.getPrimaryEmail());
                        data.put(CLIENT_ID, clientId);
                        data.put(REDIRECT_URI, redirectUri);
                        data.put(ORIGIN, user.getOrigin());
                        Timestamp expiry = new Timestamp(System.currentTimeMillis() + (INVITATION_EXPIRY_DAYS * 24 * 60 * 60 * 1000));
                        ExpiringCode code = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(data), expiry, INVITATION.name(), IdentityZoneHolder.get().getId());

                        String invitationLink = accountsUrl + "?code=" + code.getCode();
                        try {
                            URL inviteLink = new URL(invitationLink);
                            invitationsResponse.getNewInvites().add(InvitationsResponse.success(user.getPrimaryEmail(), user.getId(), user.getOrigin(), inviteLink));
                        } catch (MalformedURLException mue) {
                            invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "invitation.exception.url", String.format("Malformed url", invitationLink)));
                        }
                    } else if (providers.size() == 0) {
                        invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "provider.non-existent", "No authentication provider found."));
                    } else {
                        invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "provider.ambiguous", "Multiple authentication providers found."));
                    }
                } else{
                    invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "email.invalid", String.format(email + " is invalid email.")));
                }
            } catch (ScimResourceConflictException x) {
                invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "user.ambiguous", "Multiple users with the same origin matched to the email address."));
            } catch (UaaException uaae) {
                invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "invitation.exception", uaae.getMessage()));
            }
        }
        return new ResponseEntity<>(invitationsResponse, HttpStatus.OK);
    }

    protected ScimUser findOrCreateUser(String email, String origin) {
        email = email.trim().toLowerCase();
        List<ScimUser> results = users.query(String.format("email eq \"%s\" and origin eq \"%s\"", email, origin), IdentityZoneHolder.get().getId());
        if (results == null || results.size() == 0) {
            ScimUser user = new ScimUser(null, email, "", "");
            user.setPrimaryEmail(email.toLowerCase());
            user.setOrigin(origin);
            user.setVerified(false);
            user.setActive(true);
            return users.createUser(user, new RandomValueStringGenerator(12).generate(), IdentityZoneHolder.get().getId());
        } else if (results.size() == 1) {
            return results.get(0);
        } else {
            throw new ScimResourceConflictException(String.format("Ambiguous users found for email:%s with origin:%s", email, origin));
        }
    }

}
