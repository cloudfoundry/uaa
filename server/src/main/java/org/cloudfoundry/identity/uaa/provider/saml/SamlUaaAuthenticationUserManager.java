package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_VERIFIED_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.isAcceptedInvitationAuthentication;

/**
 * Part of the AuthenticationConverter used during SAML login flow.
 * This handles User creation and storage in the database.
 */
public class SamlUaaAuthenticationUserManager implements ApplicationEventPublisherAware {

    ApplicationEventPublisher eventPublisher;

    public SamlUaaAuthenticationUserManager(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    private final UaaUserDatabase userDatabase;

    protected UaaUser createIfMissing(UaaPrincipal samlPrincipal,
            boolean addNew,
            Collection<? extends GrantedAuthority> authorities,
            MultiValueMap<String, String> userAttributes) {

        CreateIfMissingContext context = new CreateIfMissingContext(addNew, false, new LinkedMultiValueMap<>(userAttributes));
        UaaUser user = getAcceptedInvitationUser(samlPrincipal, context);
        UaaUser userWithSamlAttributes = getUser(samlPrincipal, context.getUserAttributes());

        try {
            if (user == null) {
                user = userDatabase.retrieveUserByName(samlPrincipal.getName(), samlPrincipal.getOrigin());
            }
        } catch (UsernameNotFoundException e) {
            UaaUserPrototype uaaUser = userDatabase.retrieveUserPrototypeByEmail(userWithSamlAttributes.getEmail(), samlPrincipal.getOrigin());
            if (uaaUser != null) {
                context.setUserModified(true);
                user = new UaaUser(uaaUser.withUsername(samlPrincipal.getName()));
            } else {
                if (!context.isAddNew()) {
                    throw new SamlLoginException("SAML user does not exist. "
                            + "You can correct this by creating a shadow user for the SAML user.", e);
                }
                publish(new NewUserAuthenticatedEvent(userWithSamlAttributes));
                try {
                    user = new UaaUser(userDatabase.retrieveUserPrototypeByName(samlPrincipal.getName(), samlPrincipal.getOrigin()));
                } catch (UsernameNotFoundException ex) {
                    throw new BadCredentialsException("Unable to establish shadow user for SAML user:" + samlPrincipal.getName(), ex);
                }
            }
        }

        if (haveUserAttributesChanged(user, userWithSamlAttributes)) {
            context.setUserModified(true);
            user = user.modifyAttributes(userWithSamlAttributes.getEmail(),
                    userWithSamlAttributes.getGivenName(),
                    userWithSamlAttributes.getFamilyName(),
                    userWithSamlAttributes.getPhoneNumber(),
                    userWithSamlAttributes.getExternalId(),
                    user.isVerified() || userWithSamlAttributes.isVerified());
        }

        publish(new ExternalGroupAuthorizationEvent(user, context.isUserModified(), authorities, true));

        user = userDatabase.retrieveUserById(user.getId());
        return user;
    }

    private UaaUser getAcceptedInvitationUser(UaaPrincipal samlPrincipal, CreateIfMissingContext context) {
        if (!isAcceptedInvitationAuthentication()) {
            return null;
        }

        context.setAddNew(false);
        String invitedUserId = (String) RequestContextHolder.currentRequestAttributes().getAttribute("user_id", RequestAttributes.SCOPE_SESSION);
        UaaUser user = userDatabase.retrieveUserById(invitedUserId);
        if (context.hasEmailAttribute()) {
            if (!context.getEmailAttribute().equalsIgnoreCase(user.getEmail())) {
                throw new BadCredentialsException("SAML User email mismatch. Authenticated email doesn't match invited email.");
            }
        } else {
            context.addEmailAttribute(user.getEmail());
        }

        if (user.getUsername().equals(user.getEmail()) && !user.getUsername().equals(samlPrincipal.getName())) {
            user = user.modifyUsername(samlPrincipal.getName());
        }

        publish(new InvitedUserAuthenticatedEvent(user));
        return userDatabase.retrieveUserById(invitedUserId);
    }

    protected UaaUser getUser(UaaPrincipal principal, MultiValueMap<String, String> userAttributes) {
        if (principal.getName() == null && userAttributes.getFirst(EMAIL_ATTRIBUTE_NAME) == null) {
            throw new BadCredentialsException("Cannot determine username from credentials supplied");
        }

        String name = principal.getName();
        return UaaUser.createWithDefaults(u ->
                u.withId(OriginKeys.NotANumber)
                        .withUsername(name)
                        .withEmail(userAttributes.getFirst(EMAIL_ATTRIBUTE_NAME))
                        .withPhoneNumber(userAttributes.getFirst(PHONE_NUMBER_ATTRIBUTE_NAME))
                        .withPassword("")
                        .withGivenName(userAttributes.getFirst(GIVEN_NAME_ATTRIBUTE_NAME))
                        .withFamilyName(userAttributes.getFirst(FAMILY_NAME_ATTRIBUTE_NAME))
                        .withAuthorities(Collections.emptyList())
                        .withVerified(Boolean.parseBoolean(userAttributes.getFirst(EMAIL_VERIFIED_ATTRIBUTE_NAME)))
                        .withOrigin(principal.getOrigin() != null ? principal.getOrigin() : OriginKeys.LOGIN_SERVER)
                        .withExternalId(name)
                        .withZoneId(principal.getZoneId())
        );
    }

    protected void storeCustomAttributesAndRoles(UaaUser user, UaaAuthentication authentication) {
        userDatabase.storeUserInfo(user.getId(),
                new UserInfo()
                        .setUserAttributes(authentication.getUserAttributes())
                        .setRoles(new LinkedList<>(authentication.getExternalGroups()))
        );
    }

    protected static boolean haveUserAttributesChanged(UaaUser existingUser, UaaUser user) {
        return existingUser.isVerified() != user.isVerified() ||
                !StringUtils.equals(existingUser.getGivenName(), user.getGivenName()) ||
                !StringUtils.equals(existingUser.getFamilyName(), user.getFamilyName()) ||
                !StringUtils.equals(existingUser.getPhoneNumber(), user.getPhoneNumber()) ||
                !StringUtils.equals(existingUser.getEmail(), user.getEmail()) ||
                !StringUtils.equals(existingUser.getExternalId(), user.getExternalId());
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher;
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    @Data
    @AllArgsConstructor
    public static class CreateIfMissingContext {
        boolean addNew;
        boolean userModified;
        MultiValueMap<String, String> userAttributes;

        public String getEmailAttribute() {
            return userAttributes.getFirst(EMAIL_ATTRIBUTE_NAME);
        }

        public boolean hasEmailAttribute() {
            return userAttributes.getFirst(EMAIL_ATTRIBUTE_NAME) != null;
        }

        public void addEmailAttribute(String value) {
            userAttributes.add(EMAIL_ATTRIBUTE_NAME, value);
        }
    }
}
