package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SourcedFileTest {
    public static final String EFFECTIVELY_EMPTY_FILE_CONTENTS = "\n  \n";

    public static final String ODD_FILE_CONTENTS =
            "The\n" +
            "  quick\n" +
            "    brown\n" +
            "      fox\n" +
            "    jumped\n" +
            "  over\n" +
            "the\n" +
            "  lazy\n" +
            "    moon!\n" +
            "";

    @Test
    void loadFile() {
        assertNull( SourcedFile.loadFile( null, "test-0" ) );

        check( EFFECTIVELY_EMPTY_FILE_CONTENTS, "test-1" );
        check( ODD_FILE_CONTENTS, "test-2" );
    }

    @Test
    void loadStream() {
        ByteArrayInputStream is = new ByteArrayInputStream(ODD_FILE_CONTENTS.getBytes());
        assertNotNull( SourcedFile.loadFile( is, "test-0" ) );
    }

    @Test
    void loadEnv() {
        assertNotNull( SourcedFile.locateAndLoadLocalFile("uaa-ratelimit.yml", SourcedFileTest.class.getClassLoader().getResource("uaa-ratelimit.yml").getPath().replace("uaa-ratelimit.yml", "")));
        assertNull( SourcedFile.locateAndLoadLocalFile("", SourcedFileTest.class.getClassLoader().getResource("uaa-ratelimit.yml").getPath().replace("uaa-ratelimit.yml", "")));
        assertNull( SourcedFile.locateAndLoadLocalFile("random", "/dev"));
        assertNull( SourcedFile.locateAndLoadLocalFile("0", "/proc/1/fdinfo"));
    }

    private void check( String fileContents, String source ) {
        SourcedFile sourcedFile = SourcedFile.loadFile( inputStringFrom( fileContents ), source );
        assertNotNull( sourcedFile, source );
        assertEquals( source, sourcedFile.getSource() );
        assertEquals( fileContents, sourcedFile.getBody(), source );
    }

    InputStream inputStringFrom( String fileContents ) {
        return new ByteArrayInputStream( fileContents.getBytes( StandardCharsets.UTF_8 ) );
    }
}