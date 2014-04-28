package org.cloudfoundry.identity.uaa.scim.domain.common;

import org.codehaus.jackson.map.annotate.JsonSerialize;

public interface ScimGroupExternalMemberInterface
{
    String getGroupId();

    void setGroupId(String groupId);

    String getExternalGroup();

    void setExternalGroup(String externalGroup);
}
