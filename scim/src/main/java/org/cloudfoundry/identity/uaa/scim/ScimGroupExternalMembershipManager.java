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
package org.cloudfoundry.identity.uaa.scim;

import java.util.List;

import org.cloudfoundry.identity.uaa.scim.domain.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

public interface ScimGroupExternalMembershipManager {

    public ScimGroupExternalMember mapExternalGroup(final String groupId, final String externalGroup)
                    throws ScimResourceNotFoundException, MemberAlreadyExistsException;

    public List<ScimGroupExternalMember> getExternalGroupMapsByGroupId(final String groupId)
                    throws ScimResourceNotFoundException;

    public List<ScimGroupExternalMember> getExternalGroupMapsByExternalGroup(final String externalGroup)
                    throws ScimResourceNotFoundException;

    public List<ScimGroupExternalMember> getExternalGroupMapsByGroupName(final String groupName)
                    throws ScimResourceNotFoundException;
}
