package org.cloudfoundry.identity.uaa.util;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;

import java.util.function.Predicate;

import static org.hamcrest.Matchers.hasItem;

public final class PredicateMatcher<T> extends BaseMatcher<T> {

    private PredicateMatcher() {
    }

    private Predicate<T> predicate;

    public static <T> PredicateMatcher<T> is(Predicate<T> predicate) {
        PredicateMatcher<T> matcher = new PredicateMatcher<>();
        matcher.predicate = predicate;
        return matcher;
    }

    public static <T> PredicateMatcher<T>[] are(Predicate<T>... predicates) {
        PredicateMatcher<T>[] matchers = new PredicateMatcher[predicates.length];
        for (int i = 0; i < predicates.length; i++) {
            matchers[i] = is(predicates[i]);
        }
        return matchers;
    }

    public static <T> Matcher<Iterable<? super T>> has(Predicate<T> predicate) {
        PredicateMatcher<T> itemMatcher = is(predicate);
        return hasItem(itemMatcher);
    }

    @Override
    public boolean matches(Object item) {
        try {
            return predicate.test((T) item);
        } catch (ClassCastException ex) {
            return false;
        }
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("match for a predicate");
    }
}
