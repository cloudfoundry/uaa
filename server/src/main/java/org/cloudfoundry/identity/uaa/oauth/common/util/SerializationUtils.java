package org.cloudfoundry.identity.uaa.oauth.common.util;

import org.springframework.core.io.support.SpringFactoriesLoader;

import org.springframework.util.Assert;

import java.util.List;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 utils
 */
public class SerializationUtils {

    private static SerializationStrategy strategy = new DefaultSerializationStrategy();

    static {
        List<SerializationStrategy> strategies = SpringFactoriesLoader.loadFactories(
                SerializationStrategy.class, SerializationUtils.class.getClassLoader());
        if (strategies.size() > 1) {
            throw new IllegalArgumentException(
                    "Too many serialization strategies in META-INF/spring.factories");
        }
        if (strategies.size() == 1) {
            strategy = strategies.getFirst();
        }
    }

    /**
     * @return The current serialization strategy.
     */
    public static SerializationStrategy getSerializationStrategy() {
        return strategy;
    }

    /**
     * Sets a new serialization strategy.
     *
     * @param serializationStrategy The serialization strategy.
     */
    public static void setSerializationStrategy(SerializationStrategy serializationStrategy) {
        Assert.notNull(serializationStrategy, "serializationStrategy cannot be null");
        strategy = serializationStrategy;
    }

    public static byte[] serialize(Object object) {
        return strategy.serialize(object);
    }

    public static <T> T deserialize(byte[] byteArray) {
        return strategy.deserialize(byteArray);
    }

}