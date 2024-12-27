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

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.util.Assert;

import java.util.Arrays;

public abstract class ScimCore<T extends ScimCore> {

    public static final String[] SCHEMAS = new String[]{"urn:scim:schemas:core:1.0"};

    private String id;

    private String externalId;

    private ScimMeta meta = new ScimMeta();

    protected ScimCore(String id) {
        this.id = id;
    }

    protected ScimCore() {
    }

    public void setSchemas(String[] schemas) {
        Assert.isTrue(Arrays.equals(SCHEMAS, schemas), "Only schema '" + SCHEMAS[0] + "' is currently supported");
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getExternalId() {
        return externalId;
    }

    public ScimCore setExternalId(String externalId) {
        this.externalId = externalId;
        return this;
    }

    public ScimMeta getMeta() {
        return meta;
    }

    public void setMeta(ScimMeta meta) {
        this.meta = meta;
    }

    @JsonIgnore
    public void setVersion(int version) {
        meta.setVersion(version);
    }

    @JsonIgnore
    public int getVersion() {
        return meta.getVersion();
    }

    public String[] getSchemas() {
        return SCHEMAS;
    }

    public void patch(T patch) {
        //no op - we don't patch metadata
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : super.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof ScimCore other) {
            return id.equals(other.id);
        } else if (o instanceof String otherId) {
            return id.equals(otherId);
        }
        return false;
    }
}
