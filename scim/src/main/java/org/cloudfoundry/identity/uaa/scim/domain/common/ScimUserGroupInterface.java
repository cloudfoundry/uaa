package org.cloudfoundry.identity.uaa.scim.domain.common;

import org.cloudfoundry.identity.uaa.scim.json.ScimUserGroupJsonDeserializer;
import org.codehaus.jackson.map.annotate.JsonDeserialize;


@JsonDeserialize(using = ScimUserGroupJsonDeserializer.class)
public interface ScimUserGroupInterface
{

    public static enum Type {
        DIRECT, INDIRECT
    }

    Type getType();

    void setType(Type type);

    String getValue();

    void setValue(String value);

    String getDisplay();

    void setDisplay(String display);

}
