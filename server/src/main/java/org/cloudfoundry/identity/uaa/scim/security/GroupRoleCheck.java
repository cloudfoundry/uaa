/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.scim.security;


import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

public class GroupRoleCheck {

    private final ScimGroupMembershipManager manager;

    public GroupRoleCheck(ScimGroupMembershipManager manager) {
        this.manager = manager;
    }

    public boolean isGroupWriter(HttpServletRequest request, int pathVariableIndex) {
        return isGroupRole(request, pathVariableIndex, ScimGroupMember.Role.WRITER);
    }

    public boolean isGroupReader(HttpServletRequest request, int pathVariableIndex) {
        return isGroupRole(request, pathVariableIndex, ScimGroupMember.Role.READER);
    }

    public boolean isGroupMember(HttpServletRequest request, int pathVariableIndex) {
        return isGroupRole(request, pathVariableIndex, ScimGroupMember.Role.MEMBER);
    }

    public boolean isGroupRole(HttpServletRequest request, int pathVariableIndex, ScimGroupMember.Role role) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if ( authentication!=null && authentication.getPrincipal() instanceof UaaPrincipal) {
            String userId = ((UaaPrincipal) authentication.getPrincipal()).getId();
            String path = UaaUrlUtils.getRequestPath(request);
            if (StringUtils.hasText(path)) {
                String groupId = UaaUrlUtils.extractPathVariableFromUrl(pathVariableIndex, path);
                if (manager.getMembers(groupId, role).contains(new ScimGroupMember(userId))) {
                    return true;
                }
            }
        }
        return false;
    }

}
