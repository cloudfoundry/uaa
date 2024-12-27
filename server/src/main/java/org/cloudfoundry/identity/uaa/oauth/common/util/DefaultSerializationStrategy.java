package org.cloudfoundry.identity.uaa.oauth.common.util;

import org.springframework.core.ConfigurableObjectInputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 utils
 */
public class DefaultSerializationStrategy implements SerializationStrategy {

    public byte[] serialize(Object state) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream(512);
            ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(state);
            oos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public <T> T deserialize(byte[] byteArray) {
        try (ObjectInputStream oip = createObjectInputStream(byteArray)) {
            @SuppressWarnings("unchecked")
            T result = (T) oip.readObject();
            return result;
        } catch (ClassNotFoundException | IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Creates an {@link ObjectInputStream} for deserialization.
     *
     * @param byteArray Data to be deserialized.
     * @return An instance of {@link ObjectInputStream} which should be used for deserialization.
     * @throws IOException If something went wrong.
     */
    protected ObjectInputStream createObjectInputStream(byte[] byteArray) throws IOException {
        return new ConfigurableObjectInputStream(new ByteArrayInputStream(byteArray),
                Thread.currentThread().getContextClassLoader());
    }
}
