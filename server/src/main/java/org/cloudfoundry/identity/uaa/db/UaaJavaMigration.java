package org.cloudfoundry.identity.uaa.db;

import org.flywaydb.core.api.MigrationVersion;
import org.flywaydb.core.api.migration.JavaMigration;
import org.flywaydb.core.internal.resolver.MigrationInfoHelper;
import org.flywaydb.core.internal.util.Pair;

public abstract class UaaJavaMigration implements JavaMigration {
  private final MigrationVersion version;
  private final String description;
  /**
   * Creates a new instance of a Java-based migration following Flyway's default naming convention.
   */
  public UaaJavaMigration() {
    String shortName = getClass().getSimpleName();
    String prefix = null;

    boolean repeatable = shortName.startsWith("R");

    if (shortName.startsWith("V") || repeatable) {
      prefix = shortName.substring(0, 1);
    }

    if (prefix == null) {
      version = MigrationVersion.fromVersion(shortName.substring(shortName.length()-5));
      description = shortName.contains("_") ? shortName.split("_")[0] : shortName;
    } else {
      Pair<MigrationVersion, String> info = MigrationInfoHelper.extractVersionAndDescription(shortName, prefix, "__", new String[] { "" }, repeatable);
      version = info.getLeft();
      description = info.getRight();
    }
  }


  @Override
  public MigrationVersion getVersion() {
    return version;
  }

  @Override
  public String getDescription() {
    return description;
  }

  @Override
  public Integer getChecksum() {
    return null;
  }

  @Override
  public boolean isUndo() {
    return false;
  }

  @Override
  public boolean isBaselineMigration() {
    return false;

  }

  @Override
  public boolean canExecuteInTransaction() {
    return true;
  }
}
