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
package org.cloudfoundry.identity.uaa.db.mysql;

import org.cloudfoundry.identity.uaa.db.FixFailedBackportMigrations_4_0_4;

public class V4_0_4__FixFailedBackPortMigrations extends FixFailedBackportMigrations_4_0_4 {
    public V4_0_4__FixFailedBackPortMigrations() {
        super("mysql");
    }
}
