package org.cloudfoundry.identity.uaa.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

public class MapCollector<T, K, V> implements Collector<T, HashMap<K, V>, HashMap<K, V>> {

    private final Function<T, K> keyMapper;
    private final Function<T, V> valueMapper;

    public MapCollector(Function<T, K> keyMapper, Function<T, V> valueMapper) {

        this.keyMapper = keyMapper;
        this.valueMapper = valueMapper;
    }

    @Override
    public Supplier<HashMap<K, V>> supplier() {
        return HashMap::new;
    }

    @Override
    public BiConsumer<HashMap<K, V>, T> accumulator() {
        return (m, item) -> m.put(keyMapper.apply(item), valueMapper.apply(item));
    }

    @Override
    public BinaryOperator<HashMap<K, V>> combiner() {
        return (left, right) -> {
            throw new IllegalStateException("Duplicate key %s".formatted(left));
        };
    }

    @Override
    public Function<HashMap<K, V>, HashMap<K, V>> finisher() {
        return m -> m;
    }

    @Override
    public Set<Characteristics> characteristics() {
        return Collections.singleton(Characteristics.UNORDERED);
    }
}
