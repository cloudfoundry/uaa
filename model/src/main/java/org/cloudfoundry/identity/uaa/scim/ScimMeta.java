/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.scim;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.cloudfoundry.identity.uaa.impl.JsonDateDeserializer;
import org.cloudfoundry.identity.uaa.impl.JsonDateSerializer;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimMeta {
    private int version;

    private Date created = new Date();

    private Date lastModified;

    private String[] attributes;

    public ScimMeta() {
    }

    public ScimMeta(Date created, Date lastModified, int version) {
        this.created = created;
        this.lastModified = lastModified;
        this.version = version;
    }

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

    public String[] getAttributes() {
        return attributes;
    }

    public void setAttributes(String[] attributes) {
        this.attributes = attributes;
    }
}
