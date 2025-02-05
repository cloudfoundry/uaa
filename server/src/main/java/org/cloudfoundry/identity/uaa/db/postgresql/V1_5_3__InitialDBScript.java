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
package org.cloudfoundry.identity.uaa.db.postgresql;

import org.cloudfoundry.identity.uaa.db.InitialPreDatabaseVersioningSchemaCreator;
import org.flywaydb.core.api.migration.Context;

import java.sql.Connection;

public class V1_5_3__InitialDBScript extends InitialPreDatabaseVersioningSchemaCreator {
    public V1_5_3__InitialDBScript() {
        super("postgresql");
    }

    @Override
    public void migrate(Context context) throws Exception {
        try (Connection con = context.getConfiguration().getDataSource().getConnection()) {
            super.migrate(con);
        }
    }
}
