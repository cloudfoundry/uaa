package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.util.json.JsonDateDeserializer;
import org.cloudfoundry.identity.uaa.util.json.JsonDateSerializer;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.JsonToken;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.JsonDeserializer;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.codehaus.jackson.map.exc.UnrecognizedPropertyException;

import java.io.IOException;
import java.util.Date;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
@JsonDeserialize(using = IdentityZone.IdentityZoneJsonDeserializer.class)
public class IdentityZone {

    private String id;

    private String subDomain;

    private String serviceInstanceId;

    private String name;

    private int version = 0;

    private Date created = new Date();

    private Date lastModified = new Date();

    @JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
    public Date getCreated() {
        return created;
    }

    @JsonDeserialize(using = JsonDateDeserializer.class)
    public void setCreated(Date created) {
        this.created = created;
    }

    @JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
    public Date getLastModified() {
        return lastModified;
    }

    @JsonDeserialize(using = JsonDateDeserializer.class)
    public void setLastModified(Date lastModified) {
        this.lastModified = lastModified;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public int getVersion() {
        return version;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSubDomain() {
        return subDomain;
    }

    public void setSubDomain(String subDomain) {
        this.subDomain = subDomain;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getServiceInstanceId() {
        return serviceInstanceId;
    }

    public void setServiceInstanceId(String serviceInstanceId) {
        this.serviceInstanceId = serviceInstanceId;
    }

    public static class IdentityZoneJsonDeserializer extends JsonDeserializer<IdentityZone> {
        @Override
        public IdentityZone deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
            IdentityZone idZone = new IdentityZone();

            while (jp.nextToken() != JsonToken.END_OBJECT) {
                if (jp.getCurrentToken() == JsonToken.FIELD_NAME) {
                    String fieldName = jp.getCurrentName();
                    jp.nextToken();

                    if ("id".equalsIgnoreCase(fieldName)) {
                        idZone.setId(jp.readValueAs(String.class));
                    } else if ("name".equalsIgnoreCase(fieldName)) {
                        idZone.setName(jp.readValueAs(String.class));
                    } else if ("subDomain".equalsIgnoreCase(fieldName)) {
                        idZone.setSubDomain(jp.readValueAs(String.class));
                    } else if ("serviceInstanceId".equalsIgnoreCase(fieldName)) {
                        idZone.setServiceInstanceId(jp.readValueAs(String.class));
                    } else if ("version".equalsIgnoreCase(fieldName)) {
                        idZone.setVersion(jp.readValueAs(Integer.class));
                    } else if ("lastModified".equalsIgnoreCase(fieldName)) {
                        idZone.setLastModified(jp.readValueAs(Date.class));
                    } else if ("created".equalsIgnoreCase(fieldName)) {
                        idZone.setCreated(jp.readValueAs(Date.class));
                    } else {
                        throw new UnrecognizedPropertyException("unrecognized field", jp.getCurrentLocation(),
                            IdentityZone.class, fieldName);
                    }
                }
            }
            return idZone;
        }
    }
}
