package org.cloudfoundry.identity.uaa.test;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpStatusCodeException;

public class HasStatusCode extends TypeSafeMatcher<HttpStatusCodeException> {
    private HttpStatus httpStatus;

    public HasStatusCode(HttpStatus httpStatus) {
        super();
        this.httpStatus = httpStatus;
    }

    @Override
    protected boolean matchesSafely(HttpStatusCodeException item) {
        return item.getStatusCode() == httpStatus;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("an HTTP response with status code " + httpStatus.toString());
    }

    @Override
    protected void describeMismatchSafely(HttpStatusCodeException item, Description mismatchDescription) {
        mismatchDescription.appendText("was actually " + item.getStatusCode());
    }

    public static HasStatusCode hasStatusCode(HttpStatus status) {
        return new HasStatusCode(status);
    }
}
