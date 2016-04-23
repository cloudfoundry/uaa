/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim;

import java.util.List;

import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

public interface ScimGroupExternalMembershipManager {

    ScimGroupExternalMember mapExternalGroup(String groupId, String externalGroup, String origin)
        throws ScimResourceNotFoundException, MemberAlreadyExistsException;

    ScimGroupExternalMember unmapExternalGroup(String groupId, String externalGroup, String origin)
        throws ScimResourceNotFoundException;

    List<ScimGroupExternalMember> getExternalGroupMapsByGroupId(String groupId, String origin)
        throws ScimResourceNotFoundException;

    List<ScimGroupExternalMember> getExternalGroupMapsByExternalGroup(String externalGroup, String origin)
        throws ScimResourceNotFoundException;

    List<ScimGroupExternalMember> getExternalGroupMapsByGroupName(String groupName, String origin)
        throws ScimResourceNotFoundException;

    void unmapAll(String groupId)
        throws ScimResourceNotFoundException;
}
