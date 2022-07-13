package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.util.function.Supplier;

public class Singleton<T> {
    private final Object[] INDIRECT_INSTANCE_REF = new Object[1];
    private final Supplier<T> constructor;

    public Singleton( Supplier<T> constructor ) {
        this.constructor = constructor;
    }

    public T getInstance() {
        synchronized ( INDIRECT_INSTANCE_REF ) {
            T instance = getArrayEntry();
            if ( instance == null ) {
                instance = constructor.get();
                INDIRECT_INSTANCE_REF[0] = instance;
            }
            return instance;
        }
    }

    @SuppressWarnings("unchecked")
    private T getArrayEntry() {
        return (T)INDIRECT_INSTANCE_REF[0];
    }
}
