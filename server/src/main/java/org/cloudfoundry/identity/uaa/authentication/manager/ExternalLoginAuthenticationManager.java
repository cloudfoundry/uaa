package org.cloudfoundry.identity.uaa.authentication.manager;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.authentication.AccountNotPreCreatedException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.DialableByPhone;
import org.cloudfoundry.identity.uaa.user.ExternallyIdentifiable;
import org.cloudfoundry.identity.uaa.user.Mailable;
import org.cloudfoundry.identity.uaa.user.Named;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.user.VerifiableUser;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanNameAware;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.emptySet;

public abstract class ExternalLoginAuthenticationManager<EAD extends ExternalLoginAuthenticationManager.ExternalAuthenticationDetails> implements AuthenticationManager, ApplicationEventPublisherAware, BeanNameAware {

    public static final String USER_ATTRIBUTE_PREFIX = "user.attribute.";
    private static final String FALLBACK_EMAIL_DOMAIN_TEMPLATE = "user.from.%s.cf";

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private ApplicationEventPublisher eventPublisher;

    @Getter
    @Setter
    private UaaUserDatabase userDatabase;

    private String name;

    @Getter
    @Setter
    private IdentityProviderProvisioning providerProvisioning;

    @Getter
    @Setter
    private ScimGroupExternalMembershipManager externalMembershipManager;

    public ExternalLoginAuthenticationManager(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    @Override
    public final void setApplicationEventPublisher(@NonNull ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Override
    public Authentication authenticate(Authentication request) throws AuthenticationException {
        if (logger.isDebugEnabled()) {
            logger.debug("Starting external authentication for:{}", UaaStringUtils.getCleanedUserControlString(request.toString()));
        }

        EAD authenticationData = getExternalAuthenticationDetails(request);
        if (authenticationData == null) {
            return null;
        }
        final String origin = authenticationData.getOrigin();

        UaaUser userFromRequest = getUser(request, authenticationData);
        if (userFromRequest == null) {
            return null;
        }

        UaaUser userFromDb;

        try {
            logger.debug("Searching for user by (username:{} , origin:{})", userFromRequest.getUsername(), origin);
            userFromDb = userDatabase.retrieveUserByName(userFromRequest.getUsername(), origin);
        } catch (UsernameNotFoundException e) {
            logger.debug("Searching for user by (email:{} , origin:{})", userFromRequest.getEmail(), origin);
            userFromDb = userDatabase.retrieveUserByEmail(userFromRequest.getEmail(), origin);
        }

        // Register new users automatically
        if (userFromDb == null) {
            if (!isAddNewShadowUser(origin)) {
                throw new AccountNotPreCreatedException("The user account must be pre-created. Please contact your system administrator.");
            }
            publish(new NewUserAuthenticatedEvent(userFromRequest.authorities(List.of())));
            try {
                userFromDb = userDatabase.retrieveUserByName(userFromRequest.getUsername(), origin);
            } catch (UsernameNotFoundException ex) {
                throw new BadCredentialsException("Unable to register user in internal UAA store.");
            }
        }

        //user is authenticated and exists in UAA
        UaaUser user = userAuthenticated(request, userFromRequest, userFromDb, authenticationData);

        UaaAuthenticationDetails uaaAuthenticationDetails;
        if (request.getDetails() instanceof UaaAuthenticationDetails) {
            uaaAuthenticationDetails = (UaaAuthenticationDetails) request.getDetails();
        } else {
            uaaAuthenticationDetails = UaaAuthenticationDetails.UNKNOWN;
        }
        UaaAuthentication success = new UaaAuthentication(new UaaPrincipal(user), user.getAuthorities(), uaaAuthenticationDetails);
        populateAuthenticationAttributes(success, request, authenticationData);
        publish(new IdentityProviderAuthenticationSuccessEvent(user, success, user.getOrigin(), IdentityZoneHolder.getCurrentZoneId()));
        return success;
    }

    protected void populateAuthenticationAttributes(UaaAuthentication authentication, Authentication request, EAD authenticationData) {
        if (request.getPrincipal() instanceof UserDetails userDetails) {
            authentication.setUserAttributes(getUserAttributes(userDetails, authenticationData));
            authentication.setExternalGroups(new HashSet<>(getExternalUserAuthorities(userDetails, authenticationData)));
        }

        if (authentication.getAuthenticationMethods() == null) {
            authentication.setAuthenticationMethods(new HashSet<>());
        }

        authentication.getAuthenticationMethods().add("ext");

        // persist the user attributes and external groups in the user info table if configured in the IdP
        if ((hasUserAttributes(authentication) || hasExternalGroups(authentication)) && getProviderProvisioning() != null) {
            IdentityProvider<ExternalIdentityProviderDefinition> provider = getProviderProvisioning().retrieveByOrigin(authenticationData.getOrigin(), IdentityZoneHolder.get().getId());
            if (provider.getConfig() != null && provider.getConfig().isStoreCustomAttributes()) {
                logger.debug("Storing custom attributes for user_id:{}", authentication.getPrincipal().getId());
                UserInfo userInfo = new UserInfo()
                        .setUserAttributes(authentication.getUserAttributes())
                        .setRoles(new LinkedList<>(Optional.ofNullable(authentication.getExternalGroups()).orElse(emptySet())));
                getUserDatabase().storeUserInfo(authentication.getPrincipal().getId(), userInfo);
            }
        }
    }

    private boolean hasExternalGroups(UaaAuthentication authentication) {
        return authentication.getExternalGroups() != null && !authentication.getExternalGroups().isEmpty();
    }

    private boolean hasUserAttributes(UaaAuthentication authentication) {
        return authentication.getUserAttributes() != null && !authentication.getUserAttributes().isEmpty();
    }

    protected abstract EAD getExternalAuthenticationDetails(Authentication authentication) throws AuthenticationException;

    protected abstract boolean isAddNewShadowUser(final String origin);

    protected MultiValueMap<String, String> getUserAttributes(UserDetails request, EAD authenticationData) {
        return new LinkedMultiValueMap<>();
    }

    protected abstract List<String> getExternalUserAuthorities(UserDetails request, EAD authenticationData);

    protected final void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    protected abstract UaaUser userAuthenticated(Authentication request, UaaUser userFromRequest, UaaUser userFromDb, EAD authenticationData);

    protected UaaUser getUser(Authentication request, EAD authDetails) {
        UserDetails userDetails;
        if (request.getPrincipal() instanceof UserDetails) {
            userDetails = (UserDetails) request.getPrincipal();
        } else if (request instanceof UsernamePasswordAuthenticationToken) {
            String username = request.getPrincipal().toString();
            Object credentials = request.getCredentials();
            userDetails = new User(username, credentials != null ? credentials.toString() : "",
                    true, true, true, true, UaaAuthority.USER_AUTHORITIES);
        } else if (request.getPrincipal() == null) {
            logger.debug("{}[{}] cannot process null principal", this.getClass().getName(), name);
            return null;
        } else {
            logger.debug("{}[{}] cannot process request of type: {}", this.getClass().getName(), name, request.getClass().getName());
            return null;
        }

        String name = userDetails.getUsername();
        String email = null;

        if (userDetails instanceof Mailable mailable) {
            email = mailable.getEmailAddress();

            if (name == null) {
                name = email;
            }
        }

        if (UaaStringUtils.isEmpty(email)) {
            email = generateEmailIfNullOrEmpty(name, authDetails.getOrigin());
        }

        String givenName = null;
        String familyName = null;
        if (userDetails instanceof Named names) {
            givenName = names.getGivenName();
            familyName = names.getFamilyName();
        }

        String phoneNumber = userDetails instanceof DialableByPhone dbp ? dbp.getPhoneNumber() : null;
        String externalId = userDetails instanceof ExternallyIdentifiable ei ? ei.getExternalId() : name;
        boolean verified = userDetails instanceof VerifiableUser vu && vu.isVerified();
        UaaUserPrototype userPrototype = new UaaUserPrototype()
                .withVerified(verified)
                .withUsername(name)
                .withPassword("")
                .withEmail(email)
                .withAuthorities(UaaAuthority.USER_AUTHORITIES)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withCreated(new Date())
                .withModified(new Date())
                .withOrigin(authDetails.getOrigin())
                .withExternalId(externalId)
                .withZoneId(IdentityZoneHolder.get().getId())
                .withPhoneNumber(phoneNumber);

        return new UaaUser(userPrototype);
    }

    protected static String generateEmailIfNullOrEmpty(final String name, final String origin) {
        if (name == null) {
            throw new BadCredentialsException("Cannot determine username from credentials supplied");
        }

        final String fallbackEmailDomain = FALLBACK_EMAIL_DOMAIN_TEMPLATE.formatted(origin);

        // use fallback domain if no '@' is present
        if (!name.contains("@")) {
            return name + "@" + fallbackEmailDomain;
        }

        // use as-is if it represents a valid e-mail address
        if (name.split("@").length == 2 && !name.startsWith("@") && !name.endsWith("@")) {
            return name;
        }

        // otherwise, remove any '@' characters and use fallback domain
        return name.replace("@", "") + "@" + fallbackEmailDomain;
    }

    protected final boolean haveUserAttributesChanged(UaaUser existingUser, UaaUser user) {
        return !StringUtils.equals(existingUser.getGivenName(), user.getGivenName())
                || !StringUtils.equals(existingUser.getFamilyName(), user.getFamilyName())
                || !StringUtils.equals(existingUser.getPhoneNumber(), user.getPhoneNumber())
                || !StringUtils.equals(existingUser.getEmail(), user.getEmail())
                || !StringUtils.equals(existingUser.getExternalId(), user.getExternalId());
    }

    /**
     * Determine the UAA-internal groups mapped to the given external groups as defined in the external group mappings
     * configured for the given identity provider.
     *
     * @param origin
     *         the origin key of the external identity provider
     * @param externalGroups
     *         the external groups, i.e., the values obtained from those IdP token claims that are defined in the
     *         'external_groups' attribute mapping of the IdP
     * @return the internal groups
     */
    protected final List<SimpleGrantedAuthority> evaluateExternalGroupMappings(String origin, Collection<? extends GrantedAuthority> externalGroups) {
        List<SimpleGrantedAuthority> result = new LinkedList<>();
        for (GrantedAuthority authority : externalGroups) {
            String externalGroup = authority.getAuthority();

            List<SimpleGrantedAuthority> internalGroups = externalMembershipManager
                    .getExternalGroupMapsByExternalGroup(externalGroup, origin, IdentityZoneHolder.get().getId()).stream()
                    .map(ScimGroupExternalMember::getDisplayName)
                    .map(SimpleGrantedAuthority::new)
                    .toList();

            result.addAll(internalGroups);
        }
        return result;
    }

    @Override
    public void setBeanName(@NonNull String name) {
        this.name = name;
    }

    @Data
    @Builder
    @AllArgsConstructor
    public static class ExternalAuthenticationDetails {
        private String origin;

        public ExternalAuthenticationDetails() {
            this.origin = "unknown";
        }

        public final String getOrigin() {
            return origin;
        }

        public final void setOrigin(final String origin) {
            this.origin = origin;
        }
    }
}
