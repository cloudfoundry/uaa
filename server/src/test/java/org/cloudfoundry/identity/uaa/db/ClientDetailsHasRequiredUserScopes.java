package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

@WithDatabaseContext
class ClientDetailsHasRequiredUserScopes {

    @Test
    void requiredUserGroupsIs1024(
            @Autowired DataSource dataSource
    ) throws Exception {
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
                    assertThat(columnSize).as("Table:" + rstableName + " Column:" + rscolumnName + " should be 1024 in size.").isEqualTo(1024);
                    foundColumn = true;
                    String columnType = rs.getString("TYPE_NAME");
                    assertThat("Table:" + rstableName + " Column:" + rscolumnName + " should have a column type.").as(columnType).isNotNull();
                    assertThat(columnType.toLowerCase()).as("Table:" + rstableName + " Column:" + rscolumnName + " should be varchar").isIn(Arrays.asList("varchar", "nvarchar"));
                    break;
                }
            }
            rs.close();

            assertThat(foundTable).as("I was expecting to find table: oauth_client_details").isTrue();
            assertThat(foundColumn).as("I was expecting to find column: required_user_groups").isTrue();
        }
    }
}
