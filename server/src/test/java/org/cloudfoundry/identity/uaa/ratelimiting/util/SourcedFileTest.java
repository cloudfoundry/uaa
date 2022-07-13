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