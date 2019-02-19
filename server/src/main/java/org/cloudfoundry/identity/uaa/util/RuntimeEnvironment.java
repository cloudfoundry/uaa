package org.cloudfoundry.identity.uaa.util;

public class RuntimeEnvironment {

    public int availableProcessors() {
        return Runtime.getRuntime().availableProcessors();
    }
}
