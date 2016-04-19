/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;

import javax.validation.constraints.NotNull;
import java.util.Calendar;
import java.util.Date;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class IdentityZone {
    public static final IdentityZone getUaa() {
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

    private String id;

    @NotNull
    private String subdomain;

    private IdentityZoneConfiguration config = new IdentityZoneConfiguration();


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

    public IdentityZone setCreated(Date created) {
        this.created = created;
        return this;
    }

    public Date getLastModified() {
        return lastModified;
    }

    public IdentityZone setLastModified(Date lastModified) {
        this.lastModified = lastModified;
        return this;
    }

    public IdentityZone setVersion(int version) {
        this.version = version;
        return this;
    }

    public int getVersion() {
        return version;
    }

    public String getName() {
        return name;
    }

    public IdentityZone setName(String name) {
        this.name = name;
        return this;
    }

    public String getSubdomain() {
        return subdomain;
    }

    public IdentityZone setSubdomain(String subdomain) {
        this.subdomain = subdomain;
        return this;
    }

    public String getId() {
        return id;
    }

    public IdentityZone setId(String id) {
        this.id = id;
        return this;
    }

    public String getDescription() {
        return description;
    }

    public IdentityZone setDescription(String description) {
        this.description = description;
        return this;
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

    public IdentityZone setConfig(IdentityZoneConfiguration config) {
        this.config = config;
        return this;
    }

    public IdentityZoneConfiguration getConfig() {
        return config;
    }
}
