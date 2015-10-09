package org.cloudfoundry.identity.uaa;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
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
    public static final String GROUP_ATTRIBUTE_NAME = "external_groups"; //can be a string or a list of strings
    public static final String EMAIL_ATTRIBUTE_NAME = "email"; //can be a string
    public static final String GIVEN_NAME_ATTRIBUTE_NAME = "given_name"; //can be a string
    public static final String FAMILY_NAME_ATTRIBUTE_NAME = "family_name"; //can be a string
    public static final String PHONE_NUMBER_ATTRIBUTE_NAME = "phone_number"; //can be a string

    public static final String EXTERNAL_GROUPS_WHITELIST = "externalGroupsWhitelist";
    public static final String ATTRIBUTE_MAPPINGS = "attributeMappings";

    private List<String> externalGroupsWhitelist = new LinkedList<>();
    private Map<String, Object> attributeMappings = new HashMap<>();

    public List<String> getExternalGroupsWhitelist() {
        return Collections.unmodifiableList(externalGroupsWhitelist);
    }

    public void setExternalGroupsWhitelist(List<String> externalGroupsWhitelist) {
        this.externalGroupsWhitelist = new LinkedList<>(externalGroupsWhitelist!=null ? externalGroupsWhitelist : Collections.EMPTY_LIST);
    }

    @JsonIgnore
    public void addWhiteListedGroup(String group) {
        this.externalGroupsWhitelist.add(group);
    }

    public void setAttributeMappings(Map<String, Object> attributeMappings) {
        this.attributeMappings = new HashMap<>(attributeMappings!=null?attributeMappings:Collections.EMPTY_MAP);
    }

    public Map<String, Object> getAttributeMappings() {
        return Collections.unmodifiableMap(attributeMappings);
    }

    @JsonIgnore
    public void addAttributeMapping(String key, Object value) {
        attributeMappings.put(key, value);
    }
}
