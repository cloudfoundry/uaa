package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.UaaSamlPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.NotANumber;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
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
@Slf4j
public class SamlUaaAuthenticationUserManager implements ApplicationEventPublisherAware {

    public static final String AUTHENTICATION_CONTEXT_CLASS_REFERENCE = "acr";

    ApplicationEventPublisher eventPublisher;
    private final IdentityZoneManager identityZoneManager;
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final SamlUaaAuthenticationAttributesConverter attributesConverter;
    private final SamlUaaAuthenticationAuthoritiesConverter authoritiesConverter;

    public SamlUaaAuthenticationUserManager(IdentityZoneManager identityZoneManager,
                                            final JdbcIdentityProviderProvisioning identityProviderProvisioning,
                                            UaaUserDatabase userDatabase,
                                            SamlUaaAuthenticationAttributesConverter attributesConverter,
                                            SamlUaaAuthenticationAuthoritiesConverter authoritiesConverter) {
        this.userDatabase = userDatabase;
        this.identityZoneManager = identityZoneManager;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.attributesConverter = attributesConverter;
        this.authoritiesConverter = authoritiesConverter;
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

    protected UaaAuthentication getUaaAuthentication(String subjectName, Saml2AuthenticationToken authenticationToken, String alias, List<Assertion> assertions, List<String> sessionIndexess) {
        UaaPrincipal initialPrincipal = new UaaPrincipal(NotANumber, subjectName, authenticationToken.getName(),
                alias, authenticationToken.getName(), identityZoneManager.getCurrentIdentityZoneId());
        log.debug("Mapped SAML authentication to IDP with origin '{}' and username '{}'",
                alias, initialPrincipal.getName());

        boolean addNew;
        IdentityProvider<SamlIdentityProviderDefinition> idp;
        SamlIdentityProviderDefinition samlConfig;
        try {
            IdentityProvider<?> idpConfig = identityProviderProvisioning.retrieveByOrigin(alias, identityZoneManager.getCurrentIdentityZoneId());
            if (idpConfig == null || !SAML.equals(idpConfig.getType()) || !idpConfig.isActive()) {
                throw new ProviderNotFoundException("Identity Provider has been disabled by administrator for alias:" + alias);
            }
            samlConfig = (SamlIdentityProviderDefinition) idpConfig.getConfig();
            idp = (IdentityProvider<SamlIdentityProviderDefinition>) idpConfig;
            addNew = samlConfig.isAddShadowUserOnLogin();
        } catch (EmptyResultDataAccessException x) {
            throw new ProviderNotFoundException("No SAML identity provider found in zone for alias:" + alias);
        }

        MultiValueMap<String, String> userAttributes = attributesConverter.retrieveUserAttributes(samlConfig, assertions);
        List<? extends GrantedAuthority> samlAuthorities = authoritiesConverter.retrieveSamlAuthorities(samlConfig, assertions);

        log.debug("Mapped SAML authentication to IDP with origin '{}' and username '{}'",
                idp.getOriginKey(), initialPrincipal.getName());

        UaaUser user = createIfMissing(initialPrincipal, addNew, getMappedAuthorities(
                idp, samlAuthorities), userAttributes);

        UaaAuthentication authentication = new UaaAuthentication(
                new UaaSamlPrincipal(user, sessionIndexess),
                authenticationToken.getCredentials(),
                user.getAuthorities(),
                authoritiesConverter.filterSamlAuthorities(samlConfig, samlAuthorities),
                attributesConverter.retrieveCustomUserAttributes(userAttributes),
                null,
                true, System.currentTimeMillis(),
                -1);

        authentication.setAuthenticationMethods(Set.of("ext"));
        setAuthContextClassRef(userAttributes, authentication, samlConfig);

        publish(new IdentityProviderAuthenticationSuccessEvent(user, authentication, OriginKeys.SAML, identityZoneManager.getCurrentIdentityZoneId()));

        if (samlConfig.isStoreCustomAttributes()) {
            storeCustomAttributesAndRoles(user, authentication);
        }

        AbstractSaml2AuthenticationRequest authenticationRequest = authenticationToken.getAuthenticationRequest();
        if (authenticationRequest != null) {
            String relayState = authenticationRequest.getRelayState();
            configureRelayRedirect(relayState);
        }

        return authentication;
    }

    private static void setAuthContextClassRef(MultiValueMap<String, String> userAttributes,
                                               UaaAuthentication authentication, SamlIdentityProviderDefinition samlConfig) {

        List<String> acrValues = userAttributes.get(AUTHENTICATION_CONTEXT_CLASS_REFERENCE);
        if (acrValues != null) {
            authentication.setAuthContextClassRef(Set.copyOf(acrValues));
        }

        if (samlConfig.getAuthnContext() != null) {
            assert acrValues != null;
            if (Collections.disjoint(acrValues, samlConfig.getAuthnContext())) {
                throw new BadCredentialsException(
                        "Identity Provider did not authenticate with the requested AuthnContext.");
            }
        }
    }

    private Collection<? extends GrantedAuthority> getMappedAuthorities(
            IdentityProvider<SamlIdentityProviderDefinition> idp,
            List<? extends GrantedAuthority> samlAuthorities) {
        Collection<? extends GrantedAuthority> authorities;
        SamlIdentityProviderDefinition.ExternalGroupMappingMode groupMappingMode = idp.getConfig().getGroupMappingMode();
        authorities = switch (groupMappingMode) {
            case EXPLICITLY_MAPPED -> authoritiesConverter.mapAuthorities(idp.getOriginKey(),
                    samlAuthorities, identityZoneManager.getCurrentIdentityZoneId());
            case AS_SCOPES -> List.copyOf(samlAuthorities);
        };
        return authorities;
    }

    private void configureRelayRedirect(String relayState) {
        //configure relay state
        if (UaaUrlUtils.isUrl(relayState)) {
            RequestContextHolder.currentRequestAttributes()
                    .setAttribute(
                            UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE,
                            relayState,
                            RequestAttributes.SCOPE_REQUEST
                    );
        }
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
