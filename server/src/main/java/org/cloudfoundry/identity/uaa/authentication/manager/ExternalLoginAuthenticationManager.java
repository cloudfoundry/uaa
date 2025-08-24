package org.cloudfoundry.identity.uaa.authentication.manager;

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

import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;

public class ExternalLoginAuthenticationManager<ExternalAuthenticationDetails> implements AuthenticationManager, ApplicationEventPublisherAware, BeanNameAware {

    public static final String USER_ATTRIBUTE_PREFIX = "user.attribute.";
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private ApplicationEventPublisher eventPublisher;

    private UaaUserDatabase userDatabase;

    private String name;

    private String origin = "unknown";

    private IdentityProviderProvisioning providerProvisioning;

    private ScimGroupExternalMembershipManager externalMembershipManager;


    public ExternalLoginAuthenticationManager(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    public IdentityProviderProvisioning getProviderProvisioning() {
        return providerProvisioning;
    }

    public void setProviderProvisioning(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    public ScimGroupExternalMembershipManager getExternalMembershipManager() {
        return externalMembershipManager;
    }

    public void setExternalMembershipManager(ScimGroupExternalMembershipManager externalMembershipManager) {
        this.externalMembershipManager = externalMembershipManager;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    /**
     * @param userDatabase the userDatabase to set
     */
    public void setUserDatabase(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    public UaaUserDatabase getUserDatabase() {
        return this.userDatabase;
    }

    @Override
    public Authentication authenticate(Authentication request) throws AuthenticationException {
        if (logger.isDebugEnabled()) {
            logger.debug("Starting external authentication for:{}", UaaStringUtils.getCleanedUserControlString(request.toString()));
        }
        ExternalAuthenticationDetails authenticationData = getExternalAuthenticationDetails(request);
        UaaUser userFromRequest = getUser(request, authenticationData);
        if (userFromRequest == null) {
            return null;
        }

        UaaUser userFromDb;

        try {
            logger.debug("Searching for user by (username:{} , origin:{})", userFromRequest.getUsername(), getOrigin());
            userFromDb = userDatabase.retrieveUserByName(userFromRequest.getUsername(), getOrigin());
        } catch (UsernameNotFoundException e) {
            logger.debug("Searching for user by (email:{} , origin:{})", userFromRequest.getEmail(), getOrigin());
            userFromDb = userDatabase.retrieveUserByEmail(userFromRequest.getEmail(), getOrigin());
        }

        // Register new users automatically
        if (userFromDb == null) {
            if (!isAddNewShadowUser()) {
                throw new AccountNotPreCreatedException("The user account must be pre-created. Please contact your system administrator.");
            }
            publish(new NewUserAuthenticatedEvent(userFromRequest.authorities(List.of())));
            try {
                userFromDb = userDatabase.retrieveUserByName(userFromRequest.getUsername(), getOrigin());
            } catch (UsernameNotFoundException ex) {
                throw new BadCredentialsException("Unable to register user in internal UAA store.");
            }
        }

        //user is authenticated and exists in UAA
        UaaUser user = userAuthenticated(request, userFromRequest, userFromDb);

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

    protected void populateAuthenticationAttributes(UaaAuthentication authentication, Authentication request, ExternalAuthenticationDetails authenticationData) {
        if (request.getPrincipal() instanceof UserDetails userDetails) {
            authentication.setUserAttributes(getUserAttributes(userDetails));
            authentication.setExternalGroups(new HashSet<>(getExternalUserAuthorities(userDetails)));
        }

        if (authentication.getAuthenticationMethods() == null) {
            authentication.setAuthenticationMethods(new HashSet<>());
        }
        authentication.getAuthenticationMethods().add("ext");
        if ((hasUserAttributes(authentication) || hasExternalGroups(authentication)) && getProviderProvisioning() != null) {
            IdentityProvider<ExternalIdentityProviderDefinition> provider = getProviderProvisioning().retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
            if (provider.getConfig() != null && provider.getConfig().isStoreCustomAttributes()) {
                logger.debug("Storing custom attributes for user_id:{}", authentication.getPrincipal().getId());
                UserInfo userInfo = new UserInfo()
                        .setUserAttributes(authentication.getUserAttributes())
                        .setRoles(new LinkedList<>(ofNullable(authentication.getExternalGroups()).orElse(emptySet())));
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

    protected ExternalAuthenticationDetails getExternalAuthenticationDetails(Authentication authentication) throws AuthenticationException {
        return null;
    }

    protected boolean isAddNewShadowUser() {
        return true;
    }

    protected MultiValueMap<String, String> getUserAttributes(UserDetails request) {
        return new LinkedMultiValueMap<>();
    }

    protected List<String> getExternalUserAuthorities(UserDetails request) {
        return new LinkedList<>();
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    protected UaaUser userAuthenticated(Authentication request, UaaUser userFromRequest, UaaUser userFromDb) {
        return userFromDb;
    }

    protected UaaUser getUser(Authentication request, ExternalAuthenticationDetails authDetails) {
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
            email = generateEmailIfNullOrEmpty(name);
        }

        String givenName = null;
        String familyName = null;
        if (userDetails instanceof Named names) {
            givenName = names.getGivenName();
            familyName = names.getFamilyName();
        }

        String phoneNumber = userDetails instanceof DialableByPhone dbp ? dbp.getPhoneNumber() : null;
        String externalId = userDetails instanceof ExternallyIdentifiable ei ? ei.getExternalId() : name;
        boolean verified = userDetails instanceof VerifiableUser vu ? vu.isVerified() : false;
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
                .withOrigin(getOrigin())
                .withExternalId(externalId)
                .withZoneId(IdentityZoneHolder.get().getId())
                .withPhoneNumber(phoneNumber);

        return new UaaUser(userPrototype);
    }

    protected String generateEmailIfNullOrEmpty(String name) {
        String email;
        if (name != null) {
            if (name.contains("@")) {
                if (name.split("@").length == 2 && !name.startsWith("@") && !name.endsWith("@")) {
                    email = name;
                } else {
                    email = name.replace("@", "") + "@user.from." + getOrigin() + ".cf";
                }
            } else {
                email = name + "@user.from." + getOrigin() + ".cf";
            }
        } else {
            throw new BadCredentialsException("Cannot determine username from credentials supplied");
        }
        return email;
    }

    protected boolean haveUserAttributesChanged(UaaUser existingUser, UaaUser user) {
        return !StringUtils.equals(existingUser.getGivenName(), user.getGivenName()) || !StringUtils.equals(existingUser.getFamilyName(), user.getFamilyName()) ||
                !StringUtils.equals(existingUser.getPhoneNumber(), user.getPhoneNumber()) || !StringUtils.equals(existingUser.getEmail(), user.getEmail()) || !StringUtils.equals(existingUser.getExternalId(), user.getExternalId());
    }

    protected List<SimpleGrantedAuthority> mapAuthorities(String origin, Collection<? extends GrantedAuthority> authorities) {
        List<SimpleGrantedAuthority> result = new LinkedList<>();
        for (GrantedAuthority authority : authorities) {
            String externalGroup = authority.getAuthority();
            for (ScimGroupExternalMember internalGroup : externalMembershipManager.getExternalGroupMapsByExternalGroup(externalGroup, origin, IdentityZoneHolder.get().getId())) {
                result.add(new SimpleGrantedAuthority(internalGroup.getDisplayName()));
            }
        }
        return result;
    }

    @Override
    public void setBeanName(String name) {
        this.name = name;
    }
}
