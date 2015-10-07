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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import static org.cloudfoundry.identity.uaa.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;

public class LoginSamlAuthenticationProvider extends SAMLAuthenticationProvider implements ApplicationEventPublisherAware {

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
        Collection<? extends GrantedAuthority> authorities = mapAuthorities(idp.getOriginKey(), samlConfig, samlAuthorities);
        UaaUser user = createIfMissing(samlPrincipal, addNew, authorities);
        UaaPrincipal principal = new UaaPrincipal(user);
        return new LoginSamlAuthenticationToken(principal, result).getUaaAuthentication(user.getAuthorities());
    }

    protected ExpiringUsernameAuthenticationToken getExpiringUsernameAuthenticationToken(Authentication authentication) {
        return (ExpiringUsernameAuthenticationToken)super.authenticate(authentication);
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    protected Collection<? extends GrantedAuthority> mapAuthorities(String origin, SamlIdentityProviderDefinition definition, Collection<? extends GrantedAuthority> authorities) {
        Collection<GrantedAuthority> result = Collections.EMPTY_LIST;
        if (definition!=null && definition.getExternalGroupsWhitelist()!=null) {
            List<String> whiteList = definition.getExternalGroupsWhitelist();
            result = new LinkedList<>();
            for (GrantedAuthority authority : authorities ) {
                String externalGroup = authority.getAuthority();
                if (whiteList.contains(externalGroup)) {
                    for (ScimGroupExternalMember internalGroup : externalMembershipManager.getExternalGroupMapsByExternalGroup(externalGroup, origin)) {
                        result.add(new SimpleGrantedAuthority(internalGroup.getDisplayName()));
                    }
                }
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

    protected UaaUser createIfMissing(UaaPrincipal samlPrincipal, boolean addNew, Collection<? extends GrantedAuthority> authorities) {
        boolean userModified = false;
        UaaPrincipal uaaPrincipal = samlPrincipal;
        UaaUser user;
        try {
            user = userDatabase.retrieveUserByName(uaaPrincipal.getName(), uaaPrincipal.getOrigin());
        } catch (UsernameNotFoundException e) {
            if (!addNew) {
                throw new LoginSAMLException("SAML user does not exist. "
                        + "You can correct this by creating a shadow user for the SAML user.", e);
            }
            // Register new users automatically
            publish(new NewUserAuthenticatedEvent(getUser(uaaPrincipal)));
            try {
                user = userDatabase.retrieveUserByName(uaaPrincipal.getName(), uaaPrincipal.getOrigin());
            } catch (UsernameNotFoundException ex) {
                throw new BadCredentialsException("Unable to establish shadow user for SAML user:"+ uaaPrincipal.getName());
            }
        }
        publish(
            new ExternalGroupAuthorizationEvent(
                user,
                true,
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

    protected UaaUser getUser(UaaPrincipal principal) {
        String name = principal.getName();
        String email = null;
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
        String givenName = null;
        if (givenName == null) {
            givenName = email.split("@")[0];
        }
        String familyName = null;
        if (familyName == null) {
            familyName = email.split("@")[1];
        }
        return new UaaUser(
            userId,
            name,
            "" /*zero length password for login server */,
            email,
            Collections.EMPTY_LIST,
            givenName,
            familyName,
            new Date(),
            new Date(),
            origin,
            name,
            false,
            zoneId,
            null,
            null);

    }
}
