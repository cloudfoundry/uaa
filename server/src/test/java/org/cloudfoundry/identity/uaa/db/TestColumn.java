package org.cloudfoundry.identity.uaa.db;

public class TestColumn {
    final String name;
    final String type;
    final int size;

    public TestColumn(String name, String type, int size) {
        this.name = name;
        this.type = type;
        this.size = size;
    }
}
