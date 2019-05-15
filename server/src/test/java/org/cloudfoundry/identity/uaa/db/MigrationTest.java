package org.cloudfoundry.identity.uaa.db;

public interface MigrationTest  {
    String getTargetMigration();
    void runAssertions() throws Exception;
}