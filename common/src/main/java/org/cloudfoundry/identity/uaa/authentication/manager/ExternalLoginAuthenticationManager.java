/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication.manager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.BeanNameAware;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;
import java.util.Date;
import java.util.Map;

public class ExternalLoginAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware, BeanNameAware {

    protected final Log logger = LogFactory.getLog(getClass());

    private ApplicationEventPublisher eventPublisher;

    private UaaUserDatabase userDatabase;

    private String name;

    private String origin = "unknown";

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
    public UaaUserDatabase getUserDatabase() { return this.userDatabase; }

    @Override
    public Authentication authenticate(Authentication request) throws AuthenticationException {
        UserDetails req;
        if (request.getPrincipal() instanceof UserDetails) {
            req = (UserDetails)request.getPrincipal();
        } else if (request instanceof UsernamePasswordAuthenticationToken) {
            String username = request.getPrincipal().toString();
            String password = request.getCredentials()!=null ? request.getCredentials().toString() : "";
            req = new User( username, password, true, true, true, true, UaaAuthority.USER_AUTHORITIES);
        } else if (request.getPrincipal() == null) {
            logger.debug(this.getClass().getName() + "["+name+"] cannot process null principal");
            return null;
        } else {
            logger.debug(this.getClass().getName() + "["+name+"] cannot process request of type: " + request.getClass().getName());
            return null;
        }

        UaaUser user = getUser(req, getExtendedAuthorizationInfo(request));
        boolean addnew = false;
        try {
            UaaUser temp = userDatabase.retrieveUserByName(user.getUsername(), getOrigin());
            if (temp!=null) {
                user = temp;
            } else {
                addnew = true;
            }
        } catch (UsernameNotFoundException e) {
            addnew = true;
        }
        if (addnew) {
            // Register new users automatically
            publish(new NewUserAuthenticatedEvent(user));
            try {
                user = userDatabase.retrieveUserByName(user.getUsername(), getOrigin());
            } catch (UsernameNotFoundException ex) {
                throw new BadCredentialsException("Bad credentials");
            }
        }
        //user is authenticated and exists in UAA
        user = userAuthenticated(request, user);

        UaaAuthenticationDetails uaaAuthenticationDetails = null;
        if (request.getDetails() instanceof UaaAuthenticationDetails) {
            uaaAuthenticationDetails = (UaaAuthenticationDetails)request.getDetails();
        } else {
            uaaAuthenticationDetails = UaaAuthenticationDetails.UNKNOWN;
        }
        Authentication success = new UaaAuthentication(new UaaPrincipal(user), user.getAuthorities(), uaaAuthenticationDetails);
        publish(new UserAuthenticationSuccessEvent(user, success));
        return success;
    }

    protected Map<String,String> getExtendedAuthorizationInfo(Authentication auth) {
        Object details = auth.getDetails();
        if (details!=null && details instanceof UaaAuthenticationDetails) {
            UaaAuthenticationDetails uaaAuthenticationDetails = (UaaAuthenticationDetails)details;
            Map<String, String> result = uaaAuthenticationDetails.getExtendedAuthorizationInfo();
            if (result!=null) {
                return result;
            }
        }
        return Collections.emptyMap();
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    protected UaaUser userAuthenticated(Authentication request, UaaUser user) {
        return user;
    }

    protected UaaUser getUser(UserDetails details, Map<String, String> info) {
        String name = details.getUsername();
        String email = info.get("email");
        if (name == null && email != null) {
            name = email;
        }
        if (name == null) {
            throw new BadCredentialsException("Cannot determine username from credentials supplied");
        }
        if (email == null) {
            if (name.contains("@")) {
                if (name.split("@").length == 2 && !name.startsWith("@") && !name.endsWith("@")) {
                    email = name;
                } else {
                    email = name.replaceAll("@", "") + "@user.from."+getOrigin()+".cf";
                }
            } else {
                email = name + "@user.from."+getOrigin()+".cf";
            }
        }
        String givenName = info.get("given_name");
        if (givenName == null) {
            givenName = email.split("@")[0];
        }
        String familyName = info.get("family_name");
        if (familyName == null) {
            familyName = email.split("@")[1];
        }
        return new UaaUser(
            "NaN",
            name,
            "" /*zero length password for login server */,
            email,
            UaaAuthority.USER_AUTHORITIES,
            givenName,
            familyName,
            new Date(),
            new Date(),
            origin,
            details.getUsername(),
            false,
            IdentityZoneHolder.get().getId(),
            null);
    }

    @Override
    public void setBeanName(String name) {
        this.name = name;
    }

}