package org.cloudfoundry.identity.uaa;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import java.beans.BeanInfo;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ProxyingBeanInfoMatcher<S>
        extends TypeSafeDiagnosingMatcher<S>
        implements InvocationHandler
{
    @SuppressWarnings("unchecked")
    public static <S, T extends Matcher<S>> T proxying(Class<T> proxyClass) {
        return (T) Proxy.newProxyInstance(
                proxyClass.getClassLoader(),
                new Class<?>[]{proxyClass},
                new ProxyingBeanInfoMatcher<>());
    }

    private final Map<String, Matcher<?>> propertyMatchers = new HashMap<>();

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (method.getDeclaringClass().isAssignableFrom(this.getClass())) {
            return method.invoke(this, args);
        }

        propertyMatchers.put(getPropertyName(method.getName()), getMatcher(args[0]));
        return proxy;
    }

    @Override
    protected boolean matchesSafely(S item, Description description) {
        BeanInfo info = unchecked(() -> Introspector.getBeanInfo(item.getClass()));
        Map<String, Method> propertyMap = Stream.of(info.getPropertyDescriptors()).collect(Collectors.toMap(PropertyDescriptor::getName, PropertyDescriptor::getReadMethod));

        boolean matched = true;
        for (Map.Entry<String, Matcher<?>> propertyMatcher : propertyMatchers.entrySet()) {
            Method getter = propertyMap.get(propertyMatcher.getKey());
            if (getter == null) {
                matched = false;
                description.appendText("\n").appendText(propertyMatcher.getKey()).appendText(": not found in ").appendValue(item.getClass());
                continue;
            }

            Object propertyValue = unchecked(() -> getter.invoke(item));
            if (!propertyMatcher.getValue().matches(propertyValue)) {
                matched = false;
                propertyMatcher.getValue().describeMismatch(
                        propertyValue,
                        description.appendText("\n").appendText(propertyMatcher.getKey()).appendText(": "));
            }
        }

        return matched;
    }

    @Override
    public void describeTo(Description description) {
        propertyMatchers.forEach((key, value) -> description.appendText("\n").appendText(key).appendText(": ").appendDescriptionOf(value));
    }

    private String getPropertyName(String methodName) {
        return methodName.substring(4, 5).toLowerCase() + methodName.substring(5);
    }

    private Matcher<?> getMatcher(Object arg) {
        if (arg instanceof Matcher<?> matcher) {
            return matcher;
        }

        return Matchers.equalTo(arg);
    }

    private static <T> T unchecked(UncheckedSupplier<T> f) throws RuntimeException {
        try {
            return f.get();
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    @FunctionalInterface
    private interface UncheckedSupplier<T>
    {
        T get() throws Throwable;
    }
}
