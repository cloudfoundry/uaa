/*
 * ******************************************************************************
 *  *     Cloud Foundry
 *  *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *  *
 *  *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  *     You may not use this product except in compliance with the License.
 *  *
 *  *     This product includes a number of subcomponents with
 *  *     separate copyright notices and license terms. Your use of these
 *  *     subcomponents is subject to the terms and conditions of the
 *  *     subcomponent's license, as noted in the LICENSE file.
 *  ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.db.hsqldb;

import org.cloudfoundry.identity.uaa.db.Create_Groups_For_Zones_2_5_2;

public class V2_5_3__Migrate_Groups_For_Zones extends Create_Groups_For_Zones_2_5_2 {
    @Override
    protected String getIdentifierQuoteChar() {
        return "";
    }
}
