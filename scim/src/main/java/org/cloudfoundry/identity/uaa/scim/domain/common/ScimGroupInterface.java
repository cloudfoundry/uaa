package org.cloudfoundry.identity.uaa.scim.domain.common;

import java.util.List;

import org.cloudfoundry.identity.uaa.scim.json.ScimGroupJsonDeserializer;
import org.cloudfoundry.identity.uaa.scim.json.ScimGroupJsonSerializer;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;

@JsonSerialize(using = ScimGroupJsonSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
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
