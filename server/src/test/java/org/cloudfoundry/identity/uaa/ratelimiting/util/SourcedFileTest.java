package org.cloudfoundry.identity.uaa.ratelimiting.util;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

class SourcedFileTest {
    public static final String EFFECTIVELY_EMPTY_FILE_CONTENTS = "\n  \n";

    public static final String ODD_FILE_CONTENTS =
            """
                    The
                      quick
                        brown
                          fox
                        jumped
                      over
                    the
                      lazy
                        moon!
                    """;

    @Test
    void loadFile() {
        assertThat(SourcedFile.loadFile(null, "test-0")).isNull();

        check(EFFECTIVELY_EMPTY_FILE_CONTENTS, "test-1");
        check(ODD_FILE_CONTENTS, "test-2");
    }

    @Test
    void loadStream() {
        ByteArrayInputStream is = new ByteArrayInputStream(ODD_FILE_CONTENTS.getBytes());
        assertThat(SourcedFile.loadFile(is, "test-0")).isNotNull();
    }

    @Test
    void loadEnv() {
        assertThat(SourcedFile.locateAndLoadLocalFile("uaa-ratelimit.yml", SourcedFileTest.class.getClassLoader().getResource("uaa-ratelimit.yml").getPath().replace("uaa-ratelimit.yml", ""))).isNotNull();
        assertThat(SourcedFile.locateAndLoadLocalFile("", SourcedFileTest.class.getClassLoader().getResource("uaa-ratelimit.yml").getPath().replace("uaa-ratelimit.yml", ""))).isNull();
        assertThat(SourcedFile.locateAndLoadLocalFile("random", "/dev")).isNull();
        assertThat(SourcedFile.locateAndLoadLocalFile("?", "/proc/1/fdinfo")).isNull();
    }

    @Test
    void loadStreamException() {
        InputStream in = mock(InputStream.class);
        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> SourcedFile.loadFile(in, ""));
    }

    private void check(String fileContents, String source) {
        SourcedFile sourcedFile = SourcedFile.loadFile(inputStringFrom(fileContents), source);
        assertThat(sourcedFile).as(source).isNotNull();
        assertThat(sourcedFile.getSource()).isEqualTo(source);
        assertThat(sourcedFile.getBody()).as(source).isEqualTo(fileContents);
    }

    InputStream inputStringFrom(String fileContents) {
        return new ByteArrayInputStream(fileContents.getBytes(StandardCharsets.UTF_8));
    }
}