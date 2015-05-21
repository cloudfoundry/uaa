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


import java.util.Date;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.context.SAMLMessageContext;

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

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            throw new IllegalArgumentException("Only SAMLAuthenticationToken is supported, " + authentication.getClass() + " was attempted");
        }

        IdentityZone zone = IdentityZoneHolder.get();

        SAMLAuthenticationToken token = (SAMLAuthenticationToken) authentication;
        SAMLMessageContext context = token.getCredentials();
        String alias = context.getPeerExtendedMetadata().getAlias();
        try {
            IdentityProvider idp = identityProviderProvisioning.retrieveByOrigin(alias, IdentityZoneHolder.get().getId());
            if (!idp.isActive()) {
                throw new ProviderNotFoundException("Identity Provider has been disabled by administrator.");
            }
        } catch (EmptyResultDataAccessException x) {
            throw new ProviderNotFoundException("Not identity provider found in zone.");
        }
        ExpiringUsernameAuthenticationToken result = (ExpiringUsernameAuthenticationToken)super.authenticate(authentication);
        UaaPrincipal principal = createIfMissing(new UaaPrincipal(Origin.NotANumber, result.getName(), null, alias, result.getName(), zone.getId()));
        return new LoginSamlAuthenticationToken(principal, result);
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    protected UaaPrincipal createIfMissing(UaaPrincipal principal) {
        UaaUser user = null;
        try {
            user = userDatabase.retrieveUserByName(principal.getName(), principal.getOrigin());
        } catch (UsernameNotFoundException e) {
            // Register new users automatically
            publish(new NewUserAuthenticatedEvent(getUser(principal)));
            try {
                user = userDatabase.retrieveUserByName(principal.getName(), principal.getOrigin());
            } catch (UsernameNotFoundException ex) {
                throw new BadCredentialsException("Unable to establish shadow user for SAML user:"+principal.getName());
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
            null);

    }
}
