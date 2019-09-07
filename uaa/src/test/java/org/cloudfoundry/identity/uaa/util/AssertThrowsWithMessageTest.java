package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AssertThrowsWithMessageTest {
    private static void doThrow() throws FooException {
        throw new FooException("the message");
    }

    private static void doNotThrow() {
        // do nothing
    }

    private static class FooException extends Throwable {
        FooException(String message) {
            super(message);
        }
    }

    @Test
    void test() {
        // These should not throw
        assertThrowsWithMessageThat(FooException.class, () -> doThrow(), is("the message"));
        assertThrowsWithMessageThat(Throwable.class, () -> doThrow(), is("the message"));
        assertThrowsWithMessageThat(Throwable.class, () -> doThrow(), startsWith("the mess"));

        AssertionFailedError actualException;

        // when the executable didn't throw
        actualException = assertThrows(AssertionFailedError.class, () ->
                assertThrowsWithMessageThat(FooException.class, () -> doNotThrow(), is("the message")));
        assertThat(actualException.getMessage(),
                is("Expected org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessageTest.FooException to be thrown, but nothing was thrown.")
        );

        // when the actual exception has the wrong exception type
        actualException = assertThrows(AssertionFailedError.class, () ->
                assertThrowsWithMessageThat(IllegalArgumentException.class, () -> doThrow(), is("the message")));
        assertThat(actualException.getMessage(),
                is("Unexpected exception type thrown ==> expected: <java.lang.IllegalArgumentException> but was: <org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessageTest.FooException>")
        );

        // when the message does not match
        actualException = assertThrows(AssertionFailedError.class, () ->
                assertThrowsWithMessageThat(FooException.class, () -> doThrow(), is("wrong message")));
        assertThat(actualException.getMessage(),
                is("The expected exception was thrown, but the exception's message did not match:\nExpected: is \"wrong message\"\n     but: was \"the message\"")
        );

        // when the message does not match using a different matcher
        actualException = assertThrows(AssertionFailedError.class, () ->
                assertThrowsWithMessageThat(FooException.class, () -> doThrow(), startsWith("wrong")));
        assertThat(actualException.getMessage(),
                is("The expected exception was thrown, but the exception's message did not match:\nExpected: a string starting with \"wrong\"\n     but: was \"the message\"")
        );
    }
}
