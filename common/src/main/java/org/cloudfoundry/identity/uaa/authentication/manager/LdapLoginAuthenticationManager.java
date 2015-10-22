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

import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.ldap.ExtendedLdapUserDetails;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.ldap.extension.SpringSecurityLdapTemplate;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.ldap.core.ContextSource;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.Date;

import javax.naming.directory.SearchControls;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class LdapLoginAuthenticationManager extends ExternalLoginAuthenticationManager {

    private final IdentityProviderProvisioning idpProvisioning;

    private final SpringSecurityLdapTemplate ldapTemplate;
    private final String groupSearchBase;
    private final String groupSearchFilter;

    private boolean autoAddAuthorities = false;

    public LdapLoginAuthenticationManager(IdentityProviderProvisioning idpProvisioning, ContextSource contextSource, String groupSearchBase, String groupSearchFilter, boolean searchSubtree) {
        this.idpProvisioning = idpProvisioning;
        this.groupSearchBase = groupSearchBase;
        this.groupSearchFilter = groupSearchFilter;

        if (contextSource != null) {
            ldapTemplate = new SpringSecurityLdapTemplate(contextSource);

            SearchControls searchControls = new SearchControls();
            int searchScope = searchSubtree ? SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE;
            searchControls.setSearchScope(searchScope);
            ldapTemplate.setSearchControls(searchControls);

            ldapTemplate.setIgnorePartialResultException(true);
        } else {
            ldapTemplate = null;
        }
    }

    @Override
    protected UaaUser userAuthenticated(Authentication request, UaaUser user) {
        boolean userModified = false;
        //we must check and see if the email address has changed between authentications
        if (request.getPrincipal() !=null && request.getPrincipal() instanceof ExtendedLdapUserDetails) {
            UaaUser fromRequest = getUser(request);
            if (haveUserAttributesChanged(user, fromRequest)) {
                user = user.modifyAttributes(fromRequest.getEmail(), fromRequest.getGivenName(), fromRequest.getFamilyName(), fromRequest.getPhoneNumber());
                userModified = true;
            }
        }
        ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(user, userModified, request.getAuthorities(), isAutoAddAuthorities());
        publish(event);
        return getUserDatabase().retrieveUserById(user.getId());
    }

    public boolean isAutoAddAuthorities() {
        return autoAddAuthorities;
    }

    public void setAutoAddAuthorities(boolean autoAddAuthorities) {
        this.autoAddAuthorities = autoAddAuthorities;
    }

    @Override
    protected Set<String> getExternalGroups(Object principal) {
        if(idpProvisioning == null || ldapTemplate == null) return Collections.EMPTY_SET;

        IdentityProvider idp = idpProvisioning.retrieveByOrigin(Origin.LDAP, IdentityZoneHolder.get().getId());
        LdapIdentityProviderDefinition def = idp.getConfigValue(LdapIdentityProviderDefinition.class);
        List<String> whitelist = def.getExternalGroupsWhitelist();

        Set<String> groups = new HashSet<>();

        if (principal instanceof ExtendedLdapUserDetails) {
            Set<Map<String,String[]>> userRoles = ldapTemplate.searchForMultipleAttributeValues(
                groupSearchBase,
                groupSearchFilter,
                new String[]{((ExtendedLdapUserDetails)principal).getDn()},
                new String[] {"cn"});

            for (Map<String,String[]> row : userRoles) {
                for(String groupName : row.get("cn")) {
                    if (whitelist.contains(groupName)) {
                        groups.add(groupName);
                    }
                }
            }
        }

        return groups;
    }

    private boolean haveUserAttributesChanged(UaaUser existingUser, UaaUser user) {
        if (!StringUtils.equals(existingUser.getGivenName(), user.getGivenName()) || !StringUtils.equals(existingUser.getFamilyName(), user.getFamilyName()) ||
                !StringUtils.equals(existingUser.getPhoneNumber(), user.getPhoneNumber()) || !StringUtils.equals(existingUser.getEmail(), user.getEmail())) {
            return true;
        }
        return false;
    }
}
