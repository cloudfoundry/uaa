/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.db;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.flywaydb.core.internal.util.StringUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class StoreSubDomainAsLowerCase_V2_7_3 implements SpringJdbcMigration {

    Log logger = LogFactory.getLog(StoreSubDomainAsLowerCase_V2_7_3.class);

    @Override
    public synchronized void migrate(JdbcTemplate jdbcTemplate) throws Exception {
        RandomValueStringGenerator generator = new RandomValueStringGenerator(3);
        IdentityZoneProvisioning provisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        Map<String, List<IdentityZone>> zones = new HashMap<>();
        Set<String> duplicates = new HashSet<>();
        for (IdentityZone zone : provisioning.retrieveAll()) {
            addToMap(zone, zones, duplicates);
        }
        for (String s : duplicates) {
            logger.debug("Processing zone duplicates for subdomain:" + s);
            List<IdentityZone> dupZones = zones.get(s);
            for (int i=1; dupZones.size()>1 && i<dupZones.size(); i++) {
                IdentityZone dupZone = dupZones.get(i);
                String newsubdomain = null;
                while (newsubdomain==null) {
                    String potentialsubdomain = (dupZone.getSubdomain() +"-"+ generator.generate()).toLowerCase();
                    if (zones.get(potentialsubdomain)==null) {
                        newsubdomain = potentialsubdomain;
                    }
                }
                logger.debug(String.format("Updating zone id:%s; old subdomain: %s; new subdomain: %s;", dupZone.getId(), dupZone.getSubdomain(), newsubdomain));
                dupZone.setSubdomain(newsubdomain);
                dupZone = provisioning.update(dupZone);
                zones.put(newsubdomain, Arrays.asList(dupZone));
            }
        }
        for (IdentityZone zone : provisioning.retrieveAll()) {
            String subdomain = zone.getSubdomain();
            if (StringUtils.hasText(subdomain) && !(subdomain.toLowerCase().equals(subdomain))) {
                logger.debug(String.format("Lowercasing zone subdomain for id:%s; old subdomain: %s; new subdomain: %s;", zone.getId(), zone.getSubdomain(), zone.getSubdomain().toLowerCase()));
                zone.setSubdomain(subdomain.toLowerCase());
                provisioning.update(zone);
            }

        }
    }

    private void addToMap(IdentityZone zone, Map<String, List<IdentityZone>> zones, Set<String> duplicates) {
        if (zone==null || zone.getSubdomain()==null) {
            return;
        }
        String subdomain = zone.getSubdomain().toLowerCase();
        if (zones.get(subdomain)==null) {
            List<IdentityZone> list = new LinkedList<>();
            list.add(zone);
            zones.put(subdomain, list);
        } else {
            logger.warn("Found duplicate zone for subdomain:"+subdomain);
            duplicates.add(subdomain);
            zones.get(subdomain).add(zone);
        }
    }


}
