package org.cloudfoundry.identity.uaa.invitations;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConflictException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.INVITATION;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.ORIGIN;
import static org.cloudfoundry.identity.uaa.util.DomainFilter.filter;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.HEADER;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.util.StringUtils.hasText;

@Controller
public class InvitationsEndpoint {

    private static final int INVITATION_EXPIRY_DAYS = 7;
    public static final String USER_ID = "user_id";
    public static final String EMAIL = "email";

    private final ScimUserProvisioning scimUserProvisioning;
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final MultitenantClientServices multitenantClientServices;
    private final ExpiringCodeStore expiringCodeStore;

    public InvitationsEndpoint(final ScimUserProvisioning scimUserProvisioning,
            final IdentityProviderProvisioning identityProviderProvisioning,
            final MultitenantClientServices multitenantClientServices,
            final ExpiringCodeStore expiringCodeStore) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.multitenantClientServices = multitenantClientServices;
        this.expiringCodeStore = expiringCodeStore;
    }

    @PostMapping(value = "/invite_users", consumes = "application/json")
    public ResponseEntity<InvitationsResponse> inviteUsers(@RequestBody InvitationsRequest invitations,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "redirect_uri") String redirectUri) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof OAuth2Authentication oAuth2Authentication) {

            if (clientId == null) {
                clientId = oAuth2Authentication.getOAuth2Request().getClientId();
            }
        }

        InvitationsResponse invitationsResponse = new InvitationsResponse();

        List<IdentityProvider> activeProviders = identityProviderProvisioning.retrieveActive(IdentityZoneHolder.get().getId());

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        String subdomainHeader = request.getHeader(SUBDOMAIN_HEADER);
        String zoneIdHeader = request.getHeader(HEADER);

        ClientDetails client = null;

        if (!hasText(subdomainHeader) && !hasText(zoneIdHeader)) {
            client = multitenantClientServices.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        }

        for (String email : invitations.getEmails()) {
            try {
                if (email != null && validateEmail(email)) {
                    List<IdentityProvider> providers = filter(activeProviders, client, email);
                    if (providers.size() == 1) {
                        ScimUser user = findOrCreateUser(email, providers.getFirst().getOriginKey());
                        String accountsUrl = UaaUrlUtils.getUaaUrl("/invitations/accept", !IdentityZoneHolder.isUaa(), IdentityZoneHolder.get());

                        Map<String, String> data = new HashMap<>();
                        data.put(USER_ID, user.getId());
                        data.put(EMAIL, user.getPrimaryEmail());
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
                            invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "invitation.exception.url", "Malformed url: %s".formatted(invitationLink)));
                        }
                    } else if (providers.isEmpty()) {
                        invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "provider.non-existent", "No authentication provider found."));
                    } else {
                        invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "provider.ambiguous", "Multiple authentication providers found."));
                    }
                } else {
                    invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "email.invalid",
                            email + " is invalid email."));
                }
            } catch (ScimResourceConflictException x) {
                invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "user.ambiguous", "Multiple users with the same origin matched to the email address."));
            } catch (UaaException uaae) {
                invitationsResponse.getFailedInvites().add(InvitationsResponse.failure(email, "invitation.exception", uaae.getMessage()));
            }
        }
        return new ResponseEntity<>(invitationsResponse, HttpStatus.OK);
    }

    private ScimUser findOrCreateUser(String email, String origin) {
        email = email.trim().toLowerCase();
        List<ScimUser> results = scimUserProvisioning.retrieveByEmailAndZone(email, origin, IdentityZoneHolder.get().getId());
        if (results == null || results.isEmpty()) {
            ScimUser user = new ScimUser(null, email, "", "");
            user.setPrimaryEmail(email.toLowerCase());
            user.setOrigin(origin);
            user.setVerified(false);
            user.setActive(true);
            return scimUserProvisioning.createUser(user, new RandomValueStringGenerator(12).generate(), IdentityZoneHolder.get().getId());
        } else if (results.size() == 1) {
            return results.getFirst();
        } else {
            throw new ScimResourceConflictException("Ambiguous users found for email:%s with origin:%s".formatted(email, origin));
        }
    }

    private boolean validateEmail(String email) {
        boolean valid = true;
        try {
            InternetAddress emailAddr = new InternetAddress(email);
            emailAddr.validate();
        } catch (AddressException e) {
            valid = false;
        }
        return valid;
    }
}
