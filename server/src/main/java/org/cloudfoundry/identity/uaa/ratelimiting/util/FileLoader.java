package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.io.IOException;

public interface FileLoader {
    String load()
            throws IOException;
}
