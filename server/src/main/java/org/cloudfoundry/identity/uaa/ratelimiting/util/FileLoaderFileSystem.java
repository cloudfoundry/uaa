package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class FileLoaderFileSystem implements FileLoader {
    private final Path filePath;

    public FileLoaderFileSystem( String filePath ) {
        this.filePath = Path.of( filePath );
    }

    @Override
    public String load()
            throws IOException {
        return Files.readString( filePath );
    }
}
