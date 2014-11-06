package org.cloudfoundry.identity.uaa.zone;

import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.JsonDeserializer;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;

import java.io.IOException;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
@JsonDeserialize(using = IdentityZone.IdentityZoneJsonDeserializer.class)
public class IdentityZone {

    private String id;

    private String subDomain;

    private String serviceInstanceId;

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
            return new IdentityZone();
        }
    }
}
