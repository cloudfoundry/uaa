package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.function.Supplier;

// NOT Multi-Thread safe!
public class LazyEnumerationToList<T> implements Supplier<List<T>> {
    private final Supplier<Enumeration<T>> supplier;
    private Enumeration<T> intermediateValue;
    private boolean ivPopulated;
    private List<T> value;
    private boolean vPopulated;

    public LazyEnumerationToList(Supplier<Enumeration<T>> supplier) {
        this.supplier = supplier;
    }

    public LazyEnumerationToList(Enumeration<T> values) {
        supplier = null;
        ivPopulated = true;
        intermediateValue = values;
    }

    public boolean hasValue() {
        if (!ivPopulated) {
            intermediateValue = supplier != null ? supplier.get() : null;
            ivPopulated = true;
        }
        return intermediateValue != null;
    }

    @Override
    public List<T> get() {
        if (!vPopulated) {
            value = hasValue() ? Collections.list(intermediateValue) : Collections.emptyList();
            vPopulated = true;
        }
        return value;
    }
}