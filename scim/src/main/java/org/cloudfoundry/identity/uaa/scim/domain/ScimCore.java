/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.domain;

import java.util.Arrays;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.springframework.util.Assert;

public abstract class ScimCore implements ScimCoreInterface {

    private String id;

    private String externalId;

    private ScimMeta meta = new ScimMeta();

    protected ScimCore(String id) {
        this.id = id;
    }

    protected ScimCore() {
    }

    @Override
    public void setSchemas(String[] schemas) {
        Assert.isTrue(Arrays.equals(SCHEMAS, schemas), "Only schema '" + SCHEMAS[0] + "' is currently supported");
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String getExternalId() {
        return externalId;
    }

    @Override
    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    @Override
    public ScimMeta getMeta() {
        return meta;
    }

    @Override
    public void setMeta(ScimMeta meta) {
        this.meta = meta;
    }

    @Override
    @JsonIgnore
    public void setVersion(int version) {
        meta.setVersion(version);
    }

    @Override
    @JsonIgnore
    public int getVersion() {
        return meta.getVersion();
    }

    @Override
    public String[] getSchemas() {
        return SCHEMAS;
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : super.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof ScimCore) {
            ScimCore other = (ScimCore) o;
            return id.equals(other.id);
        } else if (o instanceof String) {
            String otherId = (String) o;
            return id.equals(otherId);
        }
        return false;
    }
}
