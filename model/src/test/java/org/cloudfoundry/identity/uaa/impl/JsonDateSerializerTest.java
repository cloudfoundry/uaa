package org.cloudfoundry.identity.uaa.impl;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class JsonDateSerializerTest {

    Exception exceptionOccurred;

    @Test
    void formatting() throws IOException {
        Date now = new Date();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        JsonGenerator gen = new JsonFactory().createGenerator(bos);
        new JsonDateSerializer().serialize(now, gen, null);
        gen.close();
        assertThat(bos).hasToString("\"%s\"".formatted(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").format(now)));
    }

    @Test
    void formattingParallel() throws InterruptedException {
        Thread[] threadArray = new Thread[1000];
        for (int i = 0; i < 1000; i++) {

            threadArray[i] = new Thread(() -> {
                try {
                    Date now = new Date();
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    JsonGenerator gen = new JsonFactory().createGenerator(bos);
                    new JsonDateSerializer().serialize(now, gen, null);
                    gen.close();
                    if (!"\"%s\"".formatted(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").format(now))
                            .equals(bos.toString())) {
                        throw new Exception("Unexpected date");
                    }

                } catch (Exception e) {
                    exceptionOccurred = e;
                }
            });
        }
        for (

                int i = 0; i < 1000; i++) {
            threadArray[i].start();
        }
        for (int i = 0; i < 1000; i++) {
            threadArray[i].join();
        }
        assertThat(exceptionOccurred).isNull();
    }

}
