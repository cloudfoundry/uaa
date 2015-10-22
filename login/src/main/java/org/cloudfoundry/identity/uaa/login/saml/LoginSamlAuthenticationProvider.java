/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login.saml;


import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.login.SamlUserAuthority;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.ExternalIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME;

public class LoginSamlAuthenticationProvider extends SAMLAuthenticationProvider implements ApplicationEventPublisherAware {
    private final static Log logger = LogFactory.getLog(LoginSamlAuthenticationProvider.class);
    private UaaUserDatabase userDatabase;
    private ApplicationEventPublisher eventPublisher;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private ScimGroupExternalMembershipManager externalMembershipManager;

    public void setIdentityProviderProvisioning(IdentityProviderProvisioning identityProviderProvisioning) {
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    public void setUserDatabase(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    public void setExternalMembershipManager(ScimGroupExternalMembershipManager externalMembershipManager) {
        this.externalMembershipManager = externalMembershipManager;
    }

    @Override
    public void setUserDetails(SAMLUserDetailsService userDetails) {
        super.setUserDetails(userDetails);
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            throw new IllegalArgumentException("Only SAMLAuthenticationToken is supported, " + authentication.getClass() + " was attempted");
        }

        IdentityZone zone = IdentityZoneHolder.get();

        SAMLAuthenticationToken token = (SAMLAuthenticationToken) authentication;
        SAMLMessageContext context = token.getCredentials();
        String alias = context.getPeerExtendedMetadata().getAlias();
        boolean addNew = true;
        IdentityProvider idp;
        SamlIdentityProviderDefinition samlConfig;
        try {
            idp = identityProviderProvisioning.retrieveByOrigin(alias, IdentityZoneHolder.get().getId());
            samlConfig = idp.getConfigValue(SamlIdentityProviderDefinition.class);
            addNew = samlConfig.isAddShadowUserOnLogin();
            if (!idp.isActive()) {
                throw new ProviderNotFoundException("Identity Provider has been disabled by administrator.");
            }
        } catch (EmptyResultDataAccessException x) {
            throw new ProviderNotFoundException("Not identity provider found in zone.");
        }
        ExpiringUsernameAuthenticationToken result = getExpiringUsernameAuthenticationToken(authentication);
        UaaPrincipal samlPrincipal = new UaaPrincipal(Origin.NotANumber, result.getName(), result.getName(), alias, result.getName(), zone.getId());
        Collection<? extends GrantedAuthority> samlAuthorities = retrieveSamlAuthorities(samlConfig, (SAMLCredential) result.getCredentials());
        Collection<? extends GrantedAuthority> authorities = mapAuthorities(idp.getOriginKey(), samlAuthorities);

        Set<String> filteredExternalGroups = filterSamlAuthorities(samlConfig, samlAuthorities);
        MultiValueMap<String, String> userAttributes = retrieveUserAttributes(samlConfig, (SAMLCredential) result.getCredentials());
        UaaUser user = createIfMissing(samlPrincipal, addNew, authorities, userAttributes);
        UaaPrincipal principal = new UaaPrincipal(user);
        return new LoginSamlAuthenticationToken(principal, result).getUaaAuthentication(user.getAuthorities(), filteredExternalGroups, userAttributes);
    }

    protected ExpiringUsernameAuthenticationToken getExpiringUsernameAuthenticationToken(Authentication authentication) {
        return (ExpiringUsernameAuthenticationToken)super.authenticate(authentication);
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    private Set<String> filterSamlAuthorities(SamlIdentityProviderDefinition definition, Collection<? extends GrantedAuthority> samlAuthorities) {
        List<String> whiteList = Collections.EMPTY_LIST;
        if (definition!=null && definition.getExternalGroupsWhitelist()!=null) {
            whiteList = definition.getExternalGroupsWhitelist();
        }
        Set<String> authorities = samlAuthorities.stream().map(s -> s.getAuthority()).collect(Collectors.toSet());

        return new HashSet<>(CollectionUtils.retainAll(authorities, whiteList));
    }

    protected Collection<? extends GrantedAuthority> mapAuthorities(String origin, Collection<? extends GrantedAuthority> authorities) {
        Collection<GrantedAuthority> result = new LinkedList<>();
            for (GrantedAuthority authority : authorities ) {
                String externalGroup = authority.getAuthority();
                    for (ScimGroupExternalMember internalGroup : externalMembershipManager.getExternalGroupMapsByExternalGroup(externalGroup, origin)) {
                        result.add(new SimpleGrantedAuthority(internalGroup.getDisplayName()));
                    }
            }
        return result;
    }

    public Collection<? extends GrantedAuthority> retrieveSamlAuthorities(SamlIdentityProviderDefinition definition, SAMLCredential credential)  {
        Collection<SamlUserAuthority> authorities = new ArrayList<>();
        if (definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME)!=null) {
            List<String> groupNames = new LinkedList<>();
            if (definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME) instanceof String) {
                groupNames.add((String) definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME));
            } else if (definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME) instanceof Collection) {
                groupNames.addAll((Collection) definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME));
            }
            for (Attribute attribute : credential.getAttributes()) {
                if ((groupNames.contains(attribute.getName())) || (groupNames.contains(attribute.getFriendlyName()))) {
                    if (attribute.getAttributeValues() != null && attribute.getAttributeValues().size() > 0) {
                        for (XMLObject group : attribute.getAttributeValues()) {
                            authorities.add(new SamlUserAuthority(((XSString) group).getValue()));
                        }
                    }
                }
            }
        }
        return authorities == null ? Collections.EMPTY_LIST : authorities;
    }

    public MultiValueMap<String, String> retrieveUserAttributes(SamlIdentityProviderDefinition definition, SAMLCredential credential) {
        MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
        if (definition != null && definition.getAttributeMappings() != null) {
            for (Entry<String, Object> attributeMapping : definition.getAttributeMappings().entrySet()) {
                if (attributeMapping.getValue() instanceof  String) {
                    if (credential.getAttribute((String)attributeMapping.getValue()) != null) {
                        String key = attributeMapping.getKey();
                        int count = 0;
                        for (XMLObject xmlObject : credential.getAttribute((String) attributeMapping.getValue()).getAttributeValues()) {
                            if (xmlObject instanceof XSString) {
                                String value = ((XSString) xmlObject).getValue();
                                userAttributes.add(key, value);
                            } else {
                                logger.debug(String.format("SAML user attribute %s at index %s is not of type XSString [zone:%s, origin:%s]", key, count, definition.getZoneId(), definition.getIdpEntityAlias()));
                            }
                            count++;
                        }
                    }
                }
            }
        }
        return userAttributes;
    }

    protected UaaUser createIfMissing(UaaPrincipal samlPrincipal, boolean addNew, Collection<? extends GrantedAuthority> authorities, MultiValueMap<String,String> userAttributes) {
        boolean userModified = false;
        UaaPrincipal uaaPrincipal = samlPrincipal;
        UaaUser user;
        UaaUser userWithSamlAttributes = getUser(uaaPrincipal, userAttributes);
        try {
            user = userDatabase.retrieveUserByName(uaaPrincipal.getName(), uaaPrincipal.getOrigin());
        } catch (UsernameNotFoundException e) {
            if (!addNew) {
                throw new LoginSAMLException("SAML user does not exist. "
                        + "You can correct this by creating a shadow user for the SAML user.", e);
            }
            // Register new users automatically
            publish(new NewUserAuthenticatedEvent(userWithSamlAttributes));
            try {
                user = userDatabase.retrieveUserByName(uaaPrincipal.getName(), uaaPrincipal.getOrigin());
            } catch (UsernameNotFoundException ex) {
                throw new BadCredentialsException("Unable to establish shadow user for SAML user:"+ uaaPrincipal.getName());
            }
        }
        if (haveUserAttributesChanged(user, userWithSamlAttributes)) {
            userModified = true;
            user = user.modifyAttributes(userWithSamlAttributes.getEmail(), userWithSamlAttributes.getGivenName(), userWithSamlAttributes.getFamilyName(), userWithSamlAttributes.getPhoneNumber());
        }
        publish(
            new ExternalGroupAuthorizationEvent(
                user,
                userModified,
                authorities,
                true
            )
        );
        user = userDatabase.retrieveUserById(user.getId());
        UaaPrincipal result = new UaaPrincipal(user);
        Authentication success = new UaaAuthentication(result, user.getAuthorities(), null);
        publish(new UserAuthenticationSuccessEvent(user, success));
        return user;
    }

    protected UaaUser getUser(UaaPrincipal principal, MultiValueMap<String,String> userAttributes) {
        String name = principal.getName();
        String email = userAttributes.getFirst(EMAIL_ATTRIBUTE_NAME);
        String givenName = userAttributes.getFirst(GIVEN_NAME_ATTRIBUTE_NAME);
        String familyName = userAttributes.getFirst(FAMILY_NAME_ATTRIBUTE_NAME);
        String phoneNumber = userAttributes.getFirst(PHONE_NUMBER_ATTRIBUTE_NAME);
        String userId = Origin.NotANumber;
        String origin = principal.getOrigin()!=null?principal.getOrigin():Origin.LOGIN_SERVER;
        String zoneId = principal.getZoneId();
        if (name == null && email != null) {
            name = email;
        }
        if (name == null && Origin.NotANumber.equals(userId)) {
            throw new BadCredentialsException("Cannot determine username from credentials supplied");
        } else if (name==null) {
            //we have user_id, name is irrelevant
            name="unknown";
        }
        if (email == null) {
            if (name.contains("@")) {
                if (name.split("@").length == 2 && !name.startsWith("@") && !name.endsWith("@")) {
                    email = name;
                } else {
                    email = name.replaceAll("@", "") + "@unknown.org";
                }
            }
            else {
                email = name + "@unknown.org";
            }
        }
        if (givenName == null) {
            givenName = email.split("@")[0];
        }
        if (familyName == null) {
            familyName = email.split("@")[1];
        }
        return new UaaUser(
        new UaaUserPrototype()
            .withEmail(email)
            .withGivenName(givenName)
            .withFamilyName(familyName)
            .withPhoneNumber(phoneNumber)
            .withModified(new Date())
            .withId(userId)
            .withUsername(name)
            .withPassword("")
            .withAuthorities(Collections.EMPTY_LIST)
            .withCreated(new Date())
            .withOrigin(origin)
            .withExternalId(name)
            .withVerified(false)
            .withZoneId(zoneId)
            .withSalt(null)
            .withPasswordLastModified(null));
    }

    private boolean haveUserAttributesChanged(UaaUser existingUser, UaaUser user) {
        if (!StringUtils.equals(existingUser.getGivenName(), user.getGivenName()) || !StringUtils.equals(existingUser.getFamilyName(), user.getFamilyName()) ||
                !StringUtils.equals(existingUser.getPhoneNumber(), user.getPhoneNumber()) || !StringUtils.equals(existingUser.getEmail(), user.getEmail())) {
            return true;
        }
        return false;
    }
}
