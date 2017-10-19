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

package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.sql.SQLException;

import static java.lang.String.format;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.Assert.assertThat;

@Ignore("Only used when wanting to test millions of rows. MySQL Only")
public class LargeRevocableTokenDeleteTests extends JdbcTestBase {

    private RandomValueStringGenerator gen24 = new RandomValueStringGenerator(24);
    private RandomValueStringGenerator gen36 = new RandomValueStringGenerator(36);
    private RandomValueStringGenerator gen100 = new RandomValueStringGenerator(36);
    private long issuedAt = System.currentTimeMillis() - (1000 * 60 * 60 *24);
    private long expiredAt = System.currentTimeMillis() - (1000 * 60 * 60 *12);
    private final int rows = 500000; //10000000;
    private String scopes = "oauth.login,scim.write,clients.read,notifications.write,critical_notifications.write,emails.write,scim.userids,password.write,idps.write";
    private String header = "token_id,client_id,user_id,format,response_type,issued_at,expires_at,scope,data,identity_zone_id";
    private String data = new RandomValueStringGenerator(2000).generate();
    private JdbcRevocableTokenProvisioning provisioning;


    public String createRow(int i) throws SQLException {
        StringBuilder string = new StringBuilder("\n");
        string.append(i+"-"+ gen24.generate()); //token_id
        string.append(',').append(gen100.generate()); //client_id
        string.append(',').append(gen36.generate()); //user_id
        string.append(',').append("OPAQUE"); //format
        string.append(',').append("token"); //response_type
        string.append(',').append(issuedAt); //issued_at
        string.append(',').append(expiredAt); //expires_at
        string.append(',').append(scopes); //scope
        string.append(',').append(data); //data
        string.append(',').append("uaa"); //identity_zone_id
        return string.toString();
    }

    @After
    public void truncate() throws Exception {
        jdbcTemplate.update("truncate table revocable_tokens");
    }

    @Before
    public void createData() throws Exception {
        long start = System.currentTimeMillis(), half = start;

        File file = new File("/var/lib/mysql-files", "revocable_tokens.csv");
        if (!file.exists()) {
            FileWriter fwriter = new FileWriter(file, false);
            BufferedWriter writer = new BufferedWriter(fwriter, 1024*1024*10);
            writer.write(header);
            writer.newLine();
            for (int idx = 0; idx < rows; idx++) {
                writer.write(createRow(idx));
                writer.newLine();
            }
            half = System.currentTimeMillis();
            System.out.println("\nData generation completed in " + (half - start) + " ms");
        }
        provisioning = new JdbcRevocableTokenProvisioning(jdbcTemplate, limitSqlAdapter);

        ProcessBuilder pb = new ProcessBuilder("/usr/bin/mysqlimport",
                                               "--fields-terminated-by", ",",
                                               "--ignore-lines", "1",
                                               "--delete",
                                               "--local",
                                               "--compress",
                                               "-h", "127.0.0.1",
                                               "-u", "root",
                                               "-pchangeme",
                                               "uaa",
                                               file.getAbsolutePath());

        System.out.println("Command:\n"+pb.toString());
        pb.start().waitFor();
        System.out.println("\nDatabase load completed in "+ (System.currentTimeMillis()- half) + " ms. Total time "+(System.currentTimeMillis()-start)+" ms.");
    }

    @Test
    public void test() throws Exception {
        assertImport();
        assertTimeForSingleDelete();
        assertTimeForSingleDelete();
        assertTimeForSingleDelete();
        assertThat(provisioning.getLastExpiredRun(), equalTo(0l)); //still more data to be erased
        truncate();
        assertTimeForSingleDelete();
        assertThat(provisioning.getLastExpiredRun(), greaterThan(0l)); //no more data to be erased
    }

    public void assertTimeForSingleDelete() {
        int count = count();
        long start = System.currentTimeMillis();
        provisioning.checkExpired();
        long time = System.currentTimeMillis() - start;
        assertThat(time, lessThan(3000l));
        int newCount = count();
        if (count > 500) {
            assertThat(newCount, lessThan(count));
            assertThat(count - newCount, greaterThan(500));
        } else {
            assertThat(newCount, lessThanOrEqualTo(count));
        }
        System.err.println(format("Deleted %s rows in %s ms.", count-newCount, time));
    }

    public int assertImport() {
        int count = count();
        assertThat(count, greaterThanOrEqualTo(rows-(rows/10))); //import is a bit flaky
        return count;
    }

    public Integer count() {
        return jdbcTemplate.queryForObject("select count(*) from revocable_tokens", Integer.class);
    }
}
