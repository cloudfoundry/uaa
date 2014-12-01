package org.cloudfoundry.identity.uaa.zone;

import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;

import javax.validation.constraints.NotNull;

import java.util.Calendar;
import java.util.Date;

@JsonSerialize
@JsonDeserialize
public class IdentityZone {
    public static final IdentityZone getUaa() {
        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.set(Calendar.YEAR, 2000);
        IdentityZone uaa = new IdentityZone();
        uaa.setCreated(calendar.getTime());
        uaa.setLastModified(calendar.getTime());
        uaa.setVersion(0);
        uaa.setId("uaa");
        uaa.setName("uaa");
        uaa.setDescription("The system zone for backwards compatibility");
        uaa.setSubdomain("");
        return uaa;
    }

    private String id;

    @NotNull
    private String subdomain;


    @NotNull
    private String name;

    private int version = 0;

    private String description;

    private Date created = new Date();

    @JsonProperty("last_modified")
    private Date lastModified = new Date();

    public Date getCreated() {
        return created;
    }

    public void setCreated(Date created) {
        this.created = created;
    }

    public Date getLastModified() {
        return lastModified;
    }

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

    public String getSubdomain() {
        return subdomain;
    }

    public void setSubdomain(String subdomain) {
        this.subdomain = subdomain;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((id == null) ? 0 : id.hashCode());
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
        IdentityZone other = (IdentityZone) obj;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        return true;
    }
    
   
}
