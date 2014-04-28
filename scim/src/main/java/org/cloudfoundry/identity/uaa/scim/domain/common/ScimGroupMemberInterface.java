package org.cloudfoundry.identity.uaa.scim.domain.common;

import java.util.Arrays;
import java.util.List;

import org.codehaus.jackson.map.annotate.JsonSerialize;

public interface ScimGroupMemberInterface
{
    @JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
    public static enum Role {
        MEMBER, READER, WRITER;
    }

    @JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
    public static enum Type {
        USER, GROUP
    }

    static final List<ScimGroupMemberInterface.Role> GROUP_MEMBER = Arrays.asList(ScimGroupMemberInterface.Role.MEMBER);

    static final List<ScimGroupMemberInterface.Role> GROUP_ADMIN = Arrays.asList(ScimGroupMemberInterface.Role.READER, ScimGroupMemberInterface.Role.WRITER);

    List<ScimGroupMemberInterface.Role> getRoles();

    void setRoles(List<ScimGroupMemberInterface.Role> permissions);

    String getMemberId();

    void setMemberId(String memberId);

    ScimGroupMemberInterface.Type getType();

    void setType(ScimGroupMemberInterface.Type type);

}
