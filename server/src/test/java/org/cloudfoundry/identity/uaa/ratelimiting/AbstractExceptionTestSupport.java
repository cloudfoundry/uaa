package org.cloudfoundry.identity.uaa.ratelimiting;

import java.util.function.Supplier;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

public class AbstractExceptionTestSupport {
    @SuppressWarnings("unused")
    protected <T> void expectException(String expectedMessageOrPrefix, Supplier<T> expectedExceptionThrowingLambda) {
        expectException(expectedMessageOrPrefix, null, expectedExceptionThrowingLambda);
    }

    protected <T> void expectException(String expectedMessageOrPrefix, Class<?> expectedExceptionCauseClass, Supplier<T> expectedExceptionThrowingLambda) {
        T result;
        try {
            result = expectedExceptionThrowingLambda.get();
        }
        catch (RateLimitingConfigException e) {
            String message = e.getMessage();
            if (!expectedMessageOrPrefix.equals(message) && !message.startsWith(expectedMessageOrPrefix)) {
                fail("expected message like '" + expectedMessageOrPrefix + "', but got: " + message);
            }
            Throwable actualCause = e.getActualCause();
            if (expectedExceptionCauseClass == null) {
                checkActualCause(actualCause, message);
            } else {
                checkActualClause(actualCause, message, expectedExceptionCauseClass);
            }
            return;
        }
        fail("No exception with '" + expectedMessageOrPrefix + "' & " + expectedExceptionCauseClass +
                "\n   result: " + result);
    }

    private void checkActualCause(Throwable actualCause, String message) {
        if (actualCause != null) {
            fail("expected no actualCause, but got '" + actualCause.getClass().getSimpleName() + "' on: " + message);
        }
    }

    private void checkActualClause(Throwable actualCause, String message, Class<?> expectedExceptionCauseClass) {
        assertNotNull(actualCause, "no actualCause on: " + message);
        Class<?> actualExceptionCauseClass = actualCause.getClass();
        if (!expectedExceptionCauseClass.isAssignableFrom(actualExceptionCauseClass)) {
            fail("incompatible exceptions with '" + message + "' & " + expectedExceptionCauseClass +
                    " != " + actualExceptionCauseClass);
        }
    }
}
