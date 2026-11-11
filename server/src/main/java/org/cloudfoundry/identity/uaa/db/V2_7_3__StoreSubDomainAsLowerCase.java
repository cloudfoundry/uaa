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

import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.ZoneAlreadyExistsException;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.flywaydb.core.internal.util.StringUtils;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.*;

public class V2_7_3__StoreSubDomainAsLowerCase extends BaseJavaMigration {

    private static final int MAX_SUBDOMAIN_LENGTH = 255;
    private static final int SUFFIX_LENGTH = 3;
    private static final int MAX_RANDOM_SUFFIX_ATTEMPTS = 10;

    static final String ID_ZONE_FIELDS = "id,version,created,lastmodified,name,subdomain,description";
    static final String IDENTITY_ZONES_QUERY = "select " + ID_ZONE_FIELDS + " from identity_zone ";

    Logger logger = LoggerFactory.getLogger(V2_7_3__StoreSubDomainAsLowerCase.class);

    @Override
    public synchronized void migrate(Context context) {
        AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator(SUFFIX_LENGTH);
        Map<String, List<IdentityZone>> zones = new HashMap<>();
        Set<String> duplicates = new HashSet<>();
        JdbcTemplate jdbcTemplate = new JdbcTemplate(new SingleConnectionDataSource(
                context.getConnection(), true));
        List<IdentityZone> identityZones = retrieveIdentityZones(jdbcTemplate);
        for (IdentityZone zone : identityZones) {
            addToMap(zone, zones, duplicates);
        }

        for (String s : duplicates) {
            logger.debug("Processing zone duplicates for subdomain:{}", s);
            List<IdentityZone> dupZones = zones.get(s);
            for (int i = 1; i < dupZones.size(); i++) {
                IdentityZone dupZone = dupZones.get(i);
                String baseSubdomain = dupZone.getSubdomain().toLowerCase(Locale.ROOT);
                if (!UaaUrlUtils.isValidSubdomain(baseSubdomain)) {
                    baseSubdomain = "zone";
                }
                String newsubdomain = uniqueSubdomain(baseSubdomain, zones.keySet(), generator);
                logger.debug("Updating zone id:{}; old subdomain: {}; new subdomain: {}", dupZone.getId(), dupZone.getSubdomain(), newsubdomain);
                dupZone.setSubdomain(newsubdomain);
                dupZone = updateIdentityZone(dupZone, jdbcTemplate);
                zones.put(newsubdomain, Collections.singletonList(dupZone));
            }
        }
        for (IdentityZone zone : identityZones) {
            String subdomain = zone.getSubdomain();
            if (!StringUtils.hasText(subdomain)) {
                continue;
            }
            String normalized = subdomain.toLowerCase(Locale.ROOT);
            if (normalized.length() > MAX_SUBDOMAIN_LENGTH) {
                // Unicode lowercasing can expand legacy values. Preserve them for manual correction.
                logger.warn("Keeping legacy subdomain for zone id:{} because lowercasing exceeds {} characters.",
                        zone.getId(), MAX_SUBDOMAIN_LENGTH);
                continue;
            }
            if (!normalized.equals(subdomain)) {
                logger.debug("Lowercasing zone subdomain for id:{}; old subdomain: {}; new subdomain: {};", zone.getId(), subdomain, normalized);
                zone.setSubdomain(normalized);
                updateIdentityZone(zone, jdbcTemplate);
            }
        }
    }

    private String uniqueSubdomain(String base, Set<String> usedSubdomains,
                                   AlphanumericRandomValueStringGenerator generator) {
        for (int attempt = 0; attempt < MAX_RANDOM_SUFFIX_ATTEMPTS; attempt++) {
            String candidate = subdomainWithSuffix(base, generator.generate().toLowerCase(Locale.ROOT));
            if (!usedSubdomains.contains(candidate)) {
                return candidate;
            }
        }
        // N+1 distinct candidates guarantee a free name among N reserved names, even if randomness stalls.
        for (long counter = 0; counter <= usedSubdomains.size(); counter++) {
            String candidate = subdomainWithSuffix(base, Long.toString(counter, 36));
            if (!usedSubdomains.contains(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to allocate a unique identity-zone subdomain.");
    }

    private String subdomainWithSuffix(String base, String suffix) {
        int baseLength = Math.min(base.length(), MAX_SUBDOMAIN_LENGTH - suffix.length() - 1);
        return base.substring(0, baseLength) + "-" + suffix;
    }

    private IdentityZone updateIdentityZone(IdentityZone identityZone, JdbcTemplate jdbcTemplate) {
        String updateIdentityZoneSql = "update identity_zone set version=?,lastmodified=?,name=?,subdomain=?,description=? where id=?";

        try {
            jdbcTemplate.update(updateIdentityZoneSql, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setInt(1, identityZone.getVersion() + 1);
                    ps.setTimestamp(2, new Timestamp(new Date().getTime()));
                    ps.setString(3, identityZone.getName());
                    ps.setString(4, identityZone.getSubdomain().toLowerCase(Locale.ROOT));
                    ps.setString(5, identityZone.getDescription());
                    ps.setString(6, identityZone.getId().trim());
                }
            });
        } catch (DuplicateKeyException e) {
            //duplicate subdomain
            throw new ZoneAlreadyExistsException(e.getMostSpecificCause().getMessage(), e);
        }
        return retrieveIdentityZone(identityZone.getId(), jdbcTemplate);
    }

    private IdentityZone retrieveIdentityZone(String id, JdbcTemplate jdbcTemplate) {
        String identityZoneByIdQuery = IDENTITY_ZONES_QUERY + "where id=?";
        try {
            return jdbcTemplate.queryForObject(identityZoneByIdQuery, mapper, id);
        } catch (EmptyResultDataAccessException x) {
            throw new ZoneDoesNotExistsException("Zone[" + id + "] not found.", x);
        }
    }

    private List<IdentityZone> retrieveIdentityZones(JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.query(IDENTITY_ZONES_QUERY, mapper);
    }

    private void addToMap(IdentityZone zone, Map<String, List<IdentityZone>> zones, Set<String> duplicates) {
        if (zone == null || zone.getSubdomain() == null) {
            return;
        }
        String subdomain = zone.getSubdomain().toLowerCase(Locale.ROOT);
        if (zones.get(subdomain) == null) {
            List<IdentityZone> list = new LinkedList<>();
            list.add(zone);
            zones.put(subdomain, list);
        } else {
            logger.warn("Found duplicate zone for subdomain:{}", subdomain);
            duplicates.add(subdomain);
            zones.get(subdomain).add(zone);
        }
    }

    private final RowMapper<IdentityZone> mapper = (rs, _) -> {
        IdentityZone identityZone = new IdentityZone();

        identityZone.setId(rs.getString(1).trim());
        identityZone.setVersion(rs.getInt(2));
        identityZone.setCreated(rs.getTimestamp(3));
        identityZone.setLastModified(rs.getTimestamp(4));
        identityZone.setName(rs.getString(5));
        identityZone.setSubdomain(rs.getString(6));
        identityZone.setDescription(rs.getString(7));

        return identityZone;
    };

}
