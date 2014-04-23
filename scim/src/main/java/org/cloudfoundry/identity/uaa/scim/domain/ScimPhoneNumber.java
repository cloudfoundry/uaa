package org.cloudfoundry.identity.uaa.scim.domain;

import org.codehaus.jackson.map.annotate.JsonSerialize;


@JsonSerialize(include = JsonSerialize.Inclusion.NON_DEFAULT)
public final class ScimPhoneNumber {
    private String value;

    // this should probably be an enum
    private String type;

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

}
