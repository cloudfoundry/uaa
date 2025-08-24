package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;

import jakarta.validation.constraints.NotNull;
import java.util.Calendar;
import java.util.Date;

@Data
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class IdentityZone {

    @EqualsAndHashCode.Include
    private String id;

    @NotNull
    private String subdomain;

    private IdentityZoneConfiguration config = new IdentityZoneConfiguration();

    @NotNull
    private String name;

    private int version;

    private String description;

    private Date created = new Date();

    @JsonProperty("last_modified")
    private Date lastModified = new Date();

    private boolean active = true;

    public static IdentityZone getUaa() {
        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.set(Calendar.YEAR, 2000);
        IdentityZone uaa = new IdentityZone();
        uaa.setCreated(calendar.getTime());
        uaa.setLastModified(calendar.getTime());
        uaa.setVersion(0);
        uaa.setId(OriginKeys.UAA);
        uaa.setName(OriginKeys.UAA);
        uaa.setDescription("The system zone for backwards compatibility");
        uaa.setSubdomain("");
        return uaa;
    }

    public static String getUaaZoneId() {
        return OriginKeys.UAA;
    }

    @JsonIgnore
    public boolean isUaa() {
        return OriginKeys.UAA.equals(getId());
    }
}
