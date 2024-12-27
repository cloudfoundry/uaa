/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ZoneManagementScopes {
    public static final String ZONE_ID_MATCH = "{zone.id}";
    public static final String ZONES_ZONE_ID_PREFIX = "zones.";
    public static final String ZONES_ZONE_ID_ADMIN = ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + "." + "admin";
    public static final String ZONE_SCOPES_SUFFIX = "(admin|read|clients.(admin|read|write)|scim.(create|read|write)|idps.read)$";
    public static final String ZONE_MANAGING_SCOPE_REGEX = "^zones\\.[^\\.]+\\." + ZONE_SCOPES_SUFFIX;
    public static final String[] ZONE_SWITCH_SCOPES = new String[]{
            ZONES_ZONE_ID_ADMIN,
            "uaa.admin",
            ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + ".read",
            ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + ".clients.admin",
            ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + ".clients.read",
            ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + ".clients.write",
            ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + ".scim.read",
            ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + ".scim.write",
            ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + ".scim.create",
            ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + ".idps.read",
            ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + ".idps.write",
            ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + ".sps.read",
            ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + ".sps.write",
            ZONES_ZONE_ID_PREFIX + ZONE_ID_MATCH + ".scim.invite"
    };

    public static final List<String> UAA_SCOPES = List.of(
            ZONES_ZONE_ID_PREFIX + "read",
            ZONES_ZONE_ID_PREFIX + "write",
            ZONES_ZONE_ID_PREFIX + "*.admin",
            ZONES_ZONE_ID_PREFIX + "*.read",
            ZONES_ZONE_ID_PREFIX + "*.clients.admin",
            ZONES_ZONE_ID_PREFIX + "*.clients.read",
            ZONES_ZONE_ID_PREFIX + "*.clients.write",
            ZONES_ZONE_ID_PREFIX + "*.scim.create",
            ZONES_ZONE_ID_PREFIX + "*.scim.read",
            ZONES_ZONE_ID_PREFIX + "*.scim.write",
            ZONES_ZONE_ID_PREFIX + "*.idps.read",
            ZONES_ZONE_ID_PREFIX + "*.idps.write",
            ZONES_ZONE_ID_PREFIX + "*.sps.write",
            ZONES_ZONE_ID_PREFIX + "*.sps.read",
            "sps.write",
            "sps.read",
            "idps.read",
            "idps.write",
            "clients.admin",
            "clients.write",
            "clients.read",
            "clients.secret",
            "scim.write",
            "scim.read",
            "scim.create",
            "scim.userids",
            "scim.zones",
            "groups.update",
            "password.write",
            "oauth.login",
            "uaa.admin");

    public static List<String> getSystemScopes() {
        return UAA_SCOPES
                .stream()
                .filter(s -> !s.startsWith(ZONES_ZONE_ID_PREFIX))
                .toList();
    }

    public static String[] getZoneSwitchingScopes(String identityZoneId) {
        String[] result = new String[ZONE_SWITCH_SCOPES.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = ZONE_SWITCH_SCOPES[i].replace(ZONE_ID_MATCH, identityZoneId);
        }
        return result;
    }
}
