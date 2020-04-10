package org.cloudfoundry.identity.uaa.db.postgresql;

import java.sql.Connection;
import org.cloudfoundry.identity.uaa.db.DataSourceAccessor;
import org.cloudfoundry.identity.uaa.db.InitialPreDatabaseVersioningSchemaCreator;

public class V1_5_3__InitialDBScript extends InitialPreDatabaseVersioningSchemaCreator {

  public V1_5_3__InitialDBScript() {
    super("postgresql");
  }

  @Override
  public void migrate(Connection connection) throws Exception {
    Connection con = DataSourceAccessor.getDataSource().getConnection();
    try {
      super.migrate(con);
    } finally {
      try {
        con.close();
      } catch (Exception ignore) {
      }
    }
  }
}
