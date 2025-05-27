/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.db;

import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import java.sql.Connection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;


/**
 * https://www.pivotaltracker.com/story/show/142625303
 * <p>
 * A back port of DB migration <code>4.0.1</code> to UAA 3.9.9 missed that fact that
 * several migrations where made in 3.10.0
 * This restores these migrations
 */
public class FixFailedBackportMigrations_4_0_4  extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(FixFailedBackportMigrations_4_0_4.class);

    private final String type;

    private final Map<String, String> scripts;
    private final String checkExistsSql = "SELECT count(*) FROM schema_version WHERE version = ?";

    public FixFailedBackportMigrations_4_0_4(String type) {
        this.type = type;
        LinkedHashMap<String, String> map = new LinkedHashMap<>();
        map.put("3.9.1", "V3_9_1__PasswordChangeRequired.sql");
        map.put("3.10.0", "V3_10_0__UserInfo.sql");
        map.put("3.10.1", "V3_10_1__Add_Last_Logon_To_User.sql");
        map.put("3.10.2", "V3_10_2__Add_Created_By_To_Oauth_Client_Details.sql");
        map.put("3.10.3", "V3_10_3__Add_Previous_Logon_To_User.sql");
        scripts = Collections.unmodifiableMap(map);
    }

    @Override
    public void migrate(Context context) {
        if ("hsqldb".equals(type)) {
            //we don't have this problem with hsqldb
            logger.info("Skipping 4.0.4 migration for {}, not affected by 3.9.9 back ports.", type);
            return;
        }
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        Connection connection = context.getConnection();
        SingleConnectionDataSource dataSource = new SingleConnectionDataSource(connection, true);
        JdbcTemplate template = new JdbcTemplate(dataSource);
        boolean run = false;
        for (Map.Entry<String, String> script : getScripts()) {
            int count = template.queryForObject(checkExistsSql, Integer.class, script.getKey());
            if (count == 0) {
                String path = "org/cloudfoundry/identity/uaa/db/" + type + "/" + script.getValue();
                logger.info("[4.0.4] Adding script for version %s with path %s".formatted(script.getKey(), path));
                populator.addScript(new ClassPathResource(path));
                run = true;
            }
        }
        if (run) {
            logger.info("Running missing migrations.");
            populator.setContinueOnError(false);
            populator.setIgnoreFailedDrops(true);
            populator.populate(connection);
            logger.info("Completed missing migrations.");
        } else {
            logger.info("Skipping 4.0.4 migrations, no migrations missing.");
        }
    }

    public Set<Map.Entry<String, String>> getScripts() {
        return scripts.entrySet();
    }
}
