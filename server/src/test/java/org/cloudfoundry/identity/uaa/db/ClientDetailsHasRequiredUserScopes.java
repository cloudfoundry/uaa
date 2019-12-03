package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Test;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;

import static org.hamcrest.Matchers.in;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isIn;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class ClientDetailsHasRequiredUserScopes extends JdbcTestBase {

    @Test
    public void requiredUserGroupsIs1024() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            boolean foundColumn = false;
            ResultSet rs = meta.getColumns(connection.getCatalog(), null, null, null);
            while (rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int columnSize = rs.getInt("COLUMN_SIZE");
                if ((foundTable = "oauth_client_details".equalsIgnoreCase(rstableName)) && "required_user_groups".equalsIgnoreCase(rscolumnName)) {
                    assertEquals("Table:" + rstableName + " Column:" + rscolumnName + " should be 1024 in size.", 1024, columnSize);
                    foundColumn = true;
                    String columnType = rs.getString("TYPE_NAME");
                    assertNotNull("Table:" + rstableName + " Column:" + rscolumnName + " should have a column type.", columnType);
                    assertThat("Table:" + rstableName + " Column:" + rscolumnName + " should be varchar", columnType.toLowerCase(), is(in(Arrays.asList("varchar", "nvarchar"))));
                    break;
                }
            }
            rs.close();

            assertTrue("I was expecting to find table: oauth_client_details", foundTable);
            assertTrue("I was expecting to find column: required_user_groups", foundColumn);
        }
    }
}
