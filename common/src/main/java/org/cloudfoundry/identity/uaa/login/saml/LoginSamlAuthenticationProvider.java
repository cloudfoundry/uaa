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
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.context.SAMLMessageContext;

import java.util.Date;

public class LoginSamlAuthenticationProvider extends SAMLAuthenticationProvider implements ApplicationEventPublisherAware {

    private UaaUserDatabase userDatabase;
    private ApplicationEventPublisher eventPublisher;
    private IdentityProviderProvisioning identityProviderProvisioning;

    public void setIdentityProviderProvisioning(IdentityProviderProvisioning identityProviderProvisioning) {
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    public void setUserDatabase(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    public ApplicationEventPublisher getApplicationEventPublisher() {
        return eventPublisher;
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
        try {
            IdentityProvider idp = identityProviderProvisioning.retrieveByOrigin(alias, IdentityZoneHolder.get().getId());
            SamlIdentityProviderDefinition samlConfig = idp.getConfigValue(SamlIdentityProviderDefinition.class);
            addNew = samlConfig.isAddShadowUserOnLogin();

            if (!idp.isActive()) {
                throw new ProviderNotFoundException("Identity Provider has been disabled by administrator.");
            }
        } catch (EmptyResultDataAccessException x) {
            throw new ProviderNotFoundException("Not identity provider found in zone.");
        }
        ExpiringUsernameAuthenticationToken result = getExpiringUsernameAuthenticationToken(authentication);
        UaaPrincipal samlPrincipal = new UaaPrincipal(Origin.NotANumber, result.getName(), result.getName(), alias, result.getName(), zone.getId());
        UaaPrincipal existingPrincipal =
            SecurityContextHolder.getContext().getAuthentication()!=null &&
                SecurityContextHolder.getContext().getAuthentication().getAuthorities().contains(UaaAuthority.UAA_INVITED) &&
                SecurityContextHolder.getContext().getAuthentication().getPrincipal() instanceof UaaPrincipal ?
                (UaaPrincipal)SecurityContextHolder.getContext().getAuthentication().getPrincipal() : null;

        UaaPrincipal principal = createIfMissing(samlPrincipal, existingPrincipal, addNew);
        return new LoginSamlAuthenticationToken(principal, result);
    }

    protected ExpiringUsernameAuthenticationToken getExpiringUsernameAuthenticationToken(Authentication authentication) {
        return (ExpiringUsernameAuthenticationToken)super.authenticate(authentication);
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    protected UaaPrincipal evaluateInvitiationPrincipal(UaaPrincipal samlPrincipal, UaaPrincipal existingPrincipal) {
        if (existingPrincipal == null) {
            //no active invitation
            return samlPrincipal;
        } else if (!samlPrincipal.getEmail().equalsIgnoreCase(existingPrincipal.getEmail())) {
            throw new BadCredentialsException("SAML User email mismatch. Authenticated email doesn't match invited email.");
        } else {
            return existingPrincipal;
        }
    }

    protected UaaPrincipal createIfMissing(UaaPrincipal samlPrincipal, UaaPrincipal existingPrincipal, boolean addNew) {
        UaaPrincipal uaaPrincipal = evaluateInvitiationPrincipal(samlPrincipal, existingPrincipal);
        UaaUser user = null;
        try {
            if (uaaPrincipal==existingPrincipal) {
                addNew = false;
                user = userDatabase.retrieveUserById(uaaPrincipal.getId());
                user = user.modifyOrigin(samlPrincipal.getOrigin());
                publish(new InvitedUserAuthenticatedEvent(user));
            } else {
                user = userDatabase.retrieveUserByName(uaaPrincipal.getName(), uaaPrincipal.getOrigin());
            }
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
        UaaPrincipal result = new UaaPrincipal(user);
        Authentication success = new UaaAuthentication(result, user.getAuthorities(), null);
        publish(new UserAuthenticationSuccessEvent(user, success));
        return result;
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
            UaaAuthority.USER_AUTHORITIES,
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
