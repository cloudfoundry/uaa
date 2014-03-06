package org.cloudfoundry.identity.uaa.db;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

@ContextConfiguration(locations = { "classpath:spring/env.xml", "classpath:spring/data-source.xml" })
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = { "postgresql","mysql" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class TableAndColumnNormalizationTest {

    private final Log logger = LogFactory.getLog(getClass());
    
    @Autowired
    private DataSource dataSource;
    
    @Test
    public void checkTables() throws Exception {
        Connection connection = dataSource.getConnection();
        try {
            DatabaseMetaData metaData = connection.getMetaData();
            ResultSet rs = metaData.getTables(null, null, null, new String[] {"TABLE"});
            int count = 0; 
            while (rs.next()) {
                String name = rs.getString("TABLE_NAME");
                logger.info("Checking table ["+name+"]");
                if (name!=null && DatabaseInformation1_5_3.tableNames.contains(name.toLowerCase())) {
                    count++;
                    logger.info("Validating table ["+name+"]");
                    assertTrue("Table["+name+"] is not lower case.", name.toLowerCase().equals(name));
                }
            }
            assertEquals("Table count:",  DatabaseInformation1_5_3.tableNames.size(), count );
            
        } finally {
            try {
                connection.close();
            } catch (Exception ignore) {}
        }
    }
    
    @Test
    public void checkColumns() throws Exception {
        Connection connection = dataSource.getConnection();
        try {
            DatabaseMetaData metaData = connection.getMetaData();
            ResultSet rs = metaData.getColumns(null, null, null, null);
            int count = 0; 
            while (rs.next()) {
                String name = rs.getString("TABLE_NAME");
                String col = rs.getString("COLUMN_NAME");
                logger.info("Checking column ["+name+"."+col+"]");
                if (name!=null && DatabaseInformation1_5_3.tableNames.contains(name.toLowerCase())) {
                    logger.info("Validating column ["+name+"."+col+"]");
                    assertTrue("Column["+name+"."+col+"] is not lower case.", col.toLowerCase().equals(col));
                }
            }
        } finally {
            try {
                connection.close();
            } catch (Exception ignore) {}
        }
    }

}
