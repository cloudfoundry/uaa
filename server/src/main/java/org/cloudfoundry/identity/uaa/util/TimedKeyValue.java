package org.cloudfoundry.identity.uaa.util;

class TimedKeyValue<K,V> {
    final long time;
    final K key;
    final V value;

    TimedKeyValue(long time, K key, V value) {
        this.time = time;
        this.value = value;
        this.key = key;
    }

    public V getValue() {
        return value;
    }

    public K getKey() {
        return key;
    }

    public long getTime() {
        return time;
    }
}
