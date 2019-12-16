package org.cloudfoundry.identity.uaa.util;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.StringDescription;
import org.junit.jupiter.api.function.Executable;
import org.junit.platform.commons.util.StringUtils;
import org.opentest4j.AssertionFailedError;

public class AssertThrowsWithMessage {
    /**
     * A customized version of org.junit.jupiter.api.AssertThrows which can also assert on the expected exception message.
     *
     * @param expectedType
     * @param executable
     * @param expectedMessageMatcher
     * @param <T>
     * @return The actual exception, when it meets the expected values.
     */
    public static <T extends Throwable> T assertThrowsWithMessageThat(Class<T> expectedType, Executable executable, Matcher<String> expectedMessageMatcher) {

        try {
            executable.execute();
        } catch (Throwable actualException) {
            if (expectedType.isInstance(actualException)) {
                String actualMessage = actualException.getMessage();
                if (expectedMessageMatcher.matches(actualMessage)) {
                    return (T) actualException;
                } else {
                    Description description = new StringDescription();
                    description.appendText("The expected exception was thrown, but the exception's message did not match:")
                            .appendText("\nExpected: ")
                            .appendDescriptionOf(expectedMessageMatcher)
                            .appendText("\n     but: ");
                    expectedMessageMatcher.describeMismatch(actualMessage, description);

                    throw new AssertionFailedError(description.toString());
                }
            } else {
                String message = format(expectedType, actualException.getClass(), "Unexpected exception type thrown");
                throw new AssertionFailedError(message, actualException);
            }
        }

        String message = String.format("Expected %s to be thrown, but nothing was thrown.", getCanonicalName(expectedType));
        throw new AssertionFailedError(message);
    }

    // All of the code below here was copy/pasted from private helpers
    // of JUnit 5's org.junit.jupiter.api.AssertionUtils.
    // Sure wish they weren't private! :)

    static String buildPrefix(String message) {
        return (StringUtils.isNotBlank(message) ? message + " ==> " : "");
    }

    static String getCanonicalName(Class<?> clazz) {
        try {
            String canonicalName = clazz.getCanonicalName();
            return (canonicalName != null ? canonicalName : clazz.getName());
        } catch (Throwable t) {
            return clazz.getName();
        }
    }

    static String format(Object expected, Object actual, String message) {
        return buildPrefix(message) + formatValues(expected, actual);
    }

    private static String toString(Object obj) {
        if (obj instanceof Class) {
            return getCanonicalName((Class<?>) obj);
        }
        return StringUtils.nullSafeToString(obj);
    }

    static String formatValues(Object expected, Object actual) {
        String expectedString = toString(expected);
        String actualString = toString(actual);
        if (expectedString.equals(actualString)) {
            return String.format("expected: %s but was: %s", formatClassAndValue(expected, expectedString),
                    formatClassAndValue(actual, actualString));
        }
        return String.format("expected: <%s> but was: <%s>", expectedString, actualString);
    }

    private static String formatClassAndValue(Object value, String valueString) {
        String classAndHash = getClassName(value) + toHash(value);
        // if it's a class, there's no need to repeat the class name contained in the valueString.
        return (value instanceof Class ? "<" + classAndHash + ">" : classAndHash + "<" + valueString + ">");
    }

    private static String toHash(Object obj) {
        return (obj == null ? "" : "@" + Integer.toHexString(System.identityHashCode(obj)));
    }

    private static String getClassName(Object obj) {
        return (obj == null ? "null"
                : obj instanceof Class ? getCanonicalName((Class<?>) obj) : obj.getClass().getName());
    }
}
