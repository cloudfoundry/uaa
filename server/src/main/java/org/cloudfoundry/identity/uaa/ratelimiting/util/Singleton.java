package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.util.function.Supplier;

public class Singleton<T> {
    private final Object[] indirectInstanceRef = new Object[1];
    private final Supplier<T> constructor;

    public Singleton(Supplier<T> constructor) {
        this.constructor = constructor;
    }

    public T getInstance() {
        synchronized (indirectInstanceRef) {
            T instance = getArrayEntry();
            if (instance == null) {
                instance = constructor.get();
                indirectInstanceRef[0] = instance;
            }
            return instance;
        }
    }

    @SuppressWarnings("unchecked")
    private T getArrayEntry() {
        return (T) indirectInstanceRef[0];
    }
}
