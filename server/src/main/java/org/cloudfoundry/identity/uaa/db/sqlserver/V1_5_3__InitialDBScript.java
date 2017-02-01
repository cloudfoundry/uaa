/*******************************************************************************
 *
 *     Copyright (c) [2016] Cloud Foundry Foundation. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.db.sqlserver;

import org.cloudfoundry.identity.uaa.db.InitialPreDatabaseVersioningSchemaCreator;

public class V1_5_3__InitialDBScript extends InitialPreDatabaseVersioningSchemaCreator {
    public V1_5_3__InitialDBScript() {
        super("sqlserver");
    }
}
