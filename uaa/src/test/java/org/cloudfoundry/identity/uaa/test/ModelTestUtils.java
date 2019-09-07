package org.cloudfoundry.identity.uaa.test;

import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.Charset;

public class ModelTestUtils {

    public static <T> String getResourceAsString(Class<T> clazz, String fileName) {
        try {
            return IOUtils.toString(clazz.getResourceAsStream(fileName), Charset.defaultCharset());
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

}
