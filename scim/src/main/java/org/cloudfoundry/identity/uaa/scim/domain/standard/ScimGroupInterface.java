package org.cloudfoundry.identity.uaa.scim.domain.standard;

import java.util.List;

import org.cloudfoundry.identity.uaa.scim.domain.common.ScimCoreInterface;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupMemberInterface;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimUserGroupInterface;
import org.cloudfoundry.identity.uaa.scim.json.ScimGroupJsonDeserializer;
import org.codehaus.jackson.map.annotate.JsonDeserialize;

@JsonDeserialize(using = ScimGroupJsonDeserializer.class)
public interface ScimGroupInterface extends ScimCoreInterface
{
    String getDisplayName();

    void setDisplayName(String displayName);

    List<? extends ScimGroupMemberInterface> getMembers();

    void setMembers(List<ScimGroupMemberInterface> members);

    /**
     * Convert to group that can be included in user object.
     * @return
     */
    ScimUserGroupInterface getUserGroup();
}
