package org.cloudfoundry.identity.uaa.test;

import org.apache.commons.io.IOUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;

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

    public static IdentityZone identityZone(String id, String subdomain) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(subdomain.toLowerCase());
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }
}
