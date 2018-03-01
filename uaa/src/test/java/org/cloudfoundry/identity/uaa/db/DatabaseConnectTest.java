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

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.junit.Test;

import static org.hamcrest.Matchers.arrayContaining;
import static org.junit.Assume.assumeThat;

public class DatabaseConnectTest extends InjectedMockContextTest {


    @Test
    public void mysql() throws Exception {
        assumeThat(getWebApplicationContext().getEnvironment().getActiveProfiles(), arrayContaining("mysql"));
    }

    @Test
    public void postgresql() throws Exception {
        assumeThat(getWebApplicationContext().getEnvironment().getActiveProfiles(), arrayContaining("postgresql"));
    }

    @Test
    public void mssql() throws Exception {
        assumeThat(getWebApplicationContext().getEnvironment().getActiveProfiles(), arrayContaining("sqlserver"));
    }

    @Test
    public void hsqldb() throws Exception {
        assumeThat(getWebApplicationContext().getEnvironment().getActiveProfiles(), arrayContaining("hsqldb"));
    }



}
