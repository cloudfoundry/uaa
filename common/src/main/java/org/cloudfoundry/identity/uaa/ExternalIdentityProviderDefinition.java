package org.cloudfoundry.identity.uaa;

import java.util.List;
import java.util.Map;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class ExternalIdentityProviderDefinition extends AbstractIdentityProviderDefinition {
    public static final String EXTERNAL_GROUPS_WHITELIST = "externalGroupsWhitelist";
    public static final String ATTRIBUTE_MAPPINGS = "attributeMappings";

    private List<String> externalGroupsWhitelist;
    private Map<String, Object> attributeMappings;

    public List<String> getExternalGroupsWhitelist() {
        return externalGroupsWhitelist;
    }

    public void setExternalGroupsWhitelist(List<String> externalGroupsWhitelist) {
        this.externalGroupsWhitelist = externalGroupsWhitelist;
    }

    public void setAttributeMappings(Map<String, Object> attributeMappings) {
        this.attributeMappings = attributeMappings;
    }

    public Map<String, Object> getAttributeMappings() {
        return attributeMappings;
    }
}
