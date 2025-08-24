package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;

import org.apache.commons.lang3.StringUtils;

import lombok.Getter;

@Getter
public class SourcedFile {
    private final String body;
    private final String source;

    public SourcedFile(String body, String source) {
        this.body = body;
        this.source = source;
    }

    public static SourcedFile locateAndLoadLocalFile(String name, String... dirs) {
        if ((name == null) || name.isBlank()) {
            return null;
        }
        for (String dir : dirs) {
            dir = StringUtils.stripToEmpty(dir);
            if (dir.startsWith("/")) {
                InputStream is = getFileInputStream(dir, name);
                if (is != null) {
                    return loadFile(is, "file(" + dir + "/" + name + ")");
                }
            }
        }
        return loadFile(getFileInputStreamFromResources(name), "resource file(/" + name + ")");
    }

    // packageFriendly for Testing
    static SourcedFile loadFile(InputStream is, String source) {
        if (is == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        try (InputStreamReader streamReader = new InputStreamReader( is, StandardCharsets.UTF_8 );
              BufferedReader reader = new BufferedReader( streamReader )) {

            for (String line; (line = reader.readLine()) != null; ) {
                sb.append(line).append('\n');
            }
        } catch (IOException e) {
            throw new IllegalStateException( "Unable to read " + source, e );
        }
        String str = sb.toString();
        return str.isEmpty() ? null : new SourcedFile( str, source );
    }

    private static InputStream getFileInputStreamFromResources(String name) {
        return SourcedFile.class.getClassLoader().getResourceAsStream("/" + name);
    }

    private static InputStream getFileInputStream(String dir, String name) {
        try {
            File file = FileSystems.getDefault().getPath(dir, name).toFile();
            if (file.isFile()) {
                return new FileInputStream( file );
            }
        } catch (IOException ignore) {
            // ignore!
        }
        return null;
    }
}
