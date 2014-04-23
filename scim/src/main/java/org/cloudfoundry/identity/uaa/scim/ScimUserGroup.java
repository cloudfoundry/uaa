package org.cloudfoundry.identity.uaa.scim;

import org.codehaus.jackson.map.annotate.JsonSerialize;

/**
 * Used to represent the array of groups contained within the user in the JSON representation of user.
 */
@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public final class ScimUserGroup {
    String value;

    String display;

    public static enum Type {
        DIRECT, INDIRECT
    };

    Type type;

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public ScimUserGroup() {
        this(null, null);
    }

    public ScimUserGroup(String value, String display) {
        this(value, display, Type.DIRECT);
    }

    public ScimUserGroup(String value, String display, Type type) {
        this.value = value;
        this.display = display;
        this.type = type;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getDisplay() {
        return display;
    }

    public void setDisplay(String display) {
        this.display = display;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((display == null) ? 0 : display.hashCode());
        result = prime * result + ((value == null) ? 0 : value.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ScimUserGroup other = (ScimUserGroup) obj;
        if (display == null) {
            if (other.display != null)
                return false;
        }
        else if (!display.equals(other.display))
            return false;
        if (value == null) {
            if (other.value != null)
                return false;
        }
        else if (!value.equals(other.value))
            return false;
        return type == other.type;
    }

    @Override
    public String toString() {
        return String.format("(id: %s, name: %s, type: %s)", value, display, type);
    }
}
