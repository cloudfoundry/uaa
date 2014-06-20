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
package org.cloudfoundry.identity.uaa.ldap;

import org.cloudfoundry.identity.uaa.authorization.ExternalGroupMappingAuthorizationManager;
import org.cloudfoundry.identity.uaa.ldap.extension.LdapAuthority;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class LdapGroupToScopesMapper implements GrantedAuthoritiesMapper {

    public ExternalGroupMappingAuthorizationManager getGroupMapper() {
        return groupMapper;
    }

    public void setGroupMapper(ExternalGroupMappingAuthorizationManager groupMapper) {
        this.groupMapper = groupMapper;
    }

    private ExternalGroupMappingAuthorizationManager groupMapper;

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        return getGroupMapper().findScopesFromAuthorities(new HashSet<>(authorities));
    }
}
