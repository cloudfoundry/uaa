package org.cloudfoundry.identity.uaa.scim.groups;

import org.codehaus.jackson.map.annotate.JsonSerialize;

import java.util.List;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public class ScimGroupMember {

    private String id;

    @JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
    public enum Type { USER, GROUP };
    private Type type;

    private List<ScimGroup.Authority> authorities;

    public List<ScimGroup.Authority> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<ScimGroup.Authority> permissions) {
        this.authorities = permissions;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    @Override
    public String toString() {
        return String.format("(memberId: %s, type: %s, permissions: %s)", id, type, authorities);
    }

    @Override
    public int hashCode() {
        int hc = 31 ^ id.hashCode();
        hc ^= type.hashCode();
        return hc;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ScimGroupMember)) {
            return false;
        }
        ScimGroupMember other = (ScimGroupMember) o;
        if (id.equals(other.id) && type.equals(other.type)) {
            return true;
        }
        return false;
    }

    public ScimGroupMember() { }

    public ScimGroupMember (String id) {
        this(id, Type.USER, ScimGroup.GROUP_MEMBER);
    }

    public ScimGroupMember (String id, Type type, List<ScimGroup.Authority> authorities) {
        this.id = id;
        this.type = type;
        this.authorities = authorities;
    }
}
