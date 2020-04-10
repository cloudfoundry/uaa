package org.cloudfoundry.identity.uaa.db;

import javax.sql.DataSource;

public class DataSourceAccessor {

  private static DataSource dataSource;

  public DataSourceAccessor() {}

  public static DataSource getDataSource() {
    return dataSource;
  }

  public void setDataSource(DataSource ds) {
    dataSource = ds;
  }
}
