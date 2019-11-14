package org.cloudfoundry.identity.uaa.impl;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class JsonDateSerializerTest {

    Exception exceptionOccured = null;

    @Test
    public void testFormatting() throws IOException {
        Date now = new Date();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        JsonGenerator gen = new JsonFactory().createGenerator(bos);
        new JsonDateSerializer().serialize(now, gen, null);
        gen.close();
        Assert.assertEquals(String.format("\"%s\"", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").format(now)),
                bos.toString());
    }

    @Test
    public void testFormattingParallel() throws InterruptedException {
        Thread[] threadArray = new Thread[1000];
        for (int i = 0; i < 1000; i++) {

            threadArray[i] = new Thread(() -> {
                try {
                    Date now = new Date();
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    JsonGenerator gen = new JsonFactory().createGenerator(bos);
                    new JsonDateSerializer().serialize(now, gen, null);
                    gen.close();
                    if (!String.format("\"%s\"", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").format(now))
                            .equals(bos.toString())) {
                        throw new Exception("Unexpected date");
                    }

                } catch (Exception e) {
                    exceptionOccured = e;
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
        Assert.assertNull(exceptionOccured);
    }

}
