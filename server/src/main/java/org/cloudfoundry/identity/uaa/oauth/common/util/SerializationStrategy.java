package org.cloudfoundry.identity.uaa.oauth.common.util;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 utils
 */
public interface SerializationStrategy {

    /**
     * Serializes an object.
     *
     * @param object The object to be serialized.
     * @return A byte array.
     */
    byte[] serialize(Object object);

    /**
     * Deserializes an object from a byte array.
     *
     * @param byteArray The byte array.
     * @param <T>       The type of the object.
     * @return The deserialized object.
     */
    <T> T deserialize(byte[] byteArray);

}
