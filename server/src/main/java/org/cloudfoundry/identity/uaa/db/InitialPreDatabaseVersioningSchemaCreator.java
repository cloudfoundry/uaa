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
package org.cloudfoundry.identity.uaa.db;

import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import java.sql.Connection;

/**
 * Created by pivotal on 2/13/14.
 *
 * This file is in place to allow FlywayDB to advance the database version to
 * 1.5.3.
 * This file, invoked by its descendants, will automatically apply the script
 * V1_5_2__initial_db.sql in order to create a database the way UAA used to
 * behave.
 * This file exists for the pure sake that it will work on existing UAA
 * databases, as well
 * as brand new databases.
 *
 */
public class InitialPreDatabaseVersioningSchemaCreator extends BaseJavaMigration {

    private final String type;

    public InitialPreDatabaseVersioningSchemaCreator(String type) {
        this.type = type;
    }

    @Override
    public void migrate(Context context) throws Exception {
        migrate(context.getConnection());
    }

    protected void migrate(Connection connection) {
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        populator.addScript(new ClassPathResource("org/cloudfoundry/identity/uaa/db/" + type
                + "/V1_5_2__initial_db.sql"));
        populator.setContinueOnError(true);
        populator.setIgnoreFailedDrops(true);
        populator.populate(connection);
    }
}
