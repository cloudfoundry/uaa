/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */
package org.cloudfoundry.identity.uaa.util;

import org.springframework.util.MultiValueMap;

import java.io.Serial;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Simple implementation of {@link org.springframework.util.MultiValueMap} that wraps a
 * {@link java.util.LinkedHashMap},
 * storing multiple values in a {@link java.util.LinkedList}.
 * <p/>
 * This Map implementation is generally not thread-safe. It is primarily
 * designed for data structures exposed from request objects, for use in a
 * single thread only.
 * <p/>
 * Enhancements from Spring Core is that we can mask values from sensitive
 * attributes such as passwords and other credentials. It also supports cyclic
 * references in the toString and hashCode methods
 *
 * @author Arjen Poutsma
 * @author Juergen Hoeller
 * @author fhanik
 * @since 3.0
 */
public class LinkedMaskingMultiValueMap<K, V> implements MultiValueMap<K, V>, Serializable {

    @Serial
    private static final long serialVersionUID = 3801124242820219132L;

    private final Map<K, List<V>> targetMap;

    private final Set<K> maskedAttributeSet = new HashSet<>();

    /**
     * Create a new LinkedMultiValueMap that wraps a {@link java.util.LinkedHashMap}.
     */
    public LinkedMaskingMultiValueMap() {
        this.targetMap = new LinkedHashMap<>();
    }

    public LinkedMaskingMultiValueMap(K maskedAttribute) {
        this.targetMap = new LinkedHashMap<>();
        this.maskedAttributeSet.add(maskedAttribute);
    }

    public LinkedMaskingMultiValueMap(K... maskedAttribute) {
        this.targetMap = new LinkedHashMap<>();
        this.maskedAttributeSet.addAll(Arrays.asList(maskedAttribute));
    }

    // masked attributes

    // MultiValueMap implementation

    @Override
    public void add(K key, V value) {
        List<V> values = this.targetMap.computeIfAbsent(key, k -> new LinkedList<>());
        values.add(value);
    }

    @Override
    public void addAll(K key, List<? extends V> values) {
        for (V value : values) {
            add(key, value);
        }
    }

    @Override
    public void addAll(MultiValueMap<K, V> values) {
        for (Entry<K, List<V>> entry : values.entrySet()) {
            addAll(entry.getKey(), entry.getValue());
        }
    }

    @Override
    public V getFirst(K key) {
        List<V> values = this.targetMap.get(key);
        return values != null ? values.getFirst() : null;
    }

    @Override
    public void set(K key, V value) {
        List<V> values = new LinkedList<>();
        values.add(value);
        this.targetMap.put(key, values);
    }

    @Override
    public void setAll(Map<K, V> values) {
        for (Entry<K, V> entry : values.entrySet()) {
            set(entry.getKey(), entry.getValue());
        }
    }

    @Override
    public Map<K, V> toSingleValueMap() {
        LinkedHashMap<K, V> singleValueMap = LinkedHashMap.newLinkedHashMap(this.targetMap.size());
        for (Entry<K, List<V>> entry : targetMap.entrySet()) {
            singleValueMap.put(entry.getKey(), entry.getValue().getFirst());
        }
        return singleValueMap;
    }

    // Map implementation

    @Override
    public int size() {
        return this.targetMap.size();
    }

    @Override
    public boolean isEmpty() {
        return this.targetMap.isEmpty();
    }

    @Override
    public boolean containsKey(Object key) {
        return this.targetMap.containsKey(key);
    }

    @Override
    public boolean containsValue(Object value) {
        return this.targetMap.containsValue(value);
    }

    @Override
    public List<V> get(Object key) {
        return this.targetMap.get(key);
    }

    @Override
    public List<V> put(K key, List<V> value) {
        return this.targetMap.put(key, value);
    }

    @Override
    public List<V> remove(Object key) {
        return this.targetMap.remove(key);
    }

    @Override
    public void putAll(Map<? extends K, ? extends List<V>> m) {
        this.targetMap.putAll(m);
    }

    @Override
    public void clear() {
        this.targetMap.clear();
    }

    @Override
    public Set<K> keySet() {
        return this.targetMap.keySet();
    }

    @Override
    public Collection<List<V>> values() {
        return this.targetMap.values();
    }

    @Override
    public Set<Entry<K, List<V>>> entrySet() {
        return this.targetMap.entrySet();
    }

    @Override
    public boolean equals(Object obj) {
        return this.targetMap.equals(obj);
    }

    @Override
    public int hashCode() {
        int h = 0;
        for (Entry<K, List<V>> entry : entrySet()) {
            int keyHash = 1;
            if (entry.getKey() == null || entry.getKey() == this) {
                // no op - don't modify the hash
            } else {
                keyHash += entry.getKey().hashCode();
            }
            List<V> value = entry.getValue();
            int valueHash = 1;
            for (V v : value) {
                valueHash = 31 * valueHash + (v == null ? 0 : v == this ? 0 : v.hashCode());
            }

            h += keyHash ^ valueHash;
        }
        return h;
    }

    @Override
    public String toString() {
        Iterator<Entry<K, List<V>>> i = targetMap.entrySet().iterator();
        if (!i.hasNext()) {
            return "{}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append('{');

        while (i.hasNext()) {

            Entry<K, List<V>> e = i.next();
            List<V> value = e.getValue();

            K key = e.getKey();
            sb.append(key == this ? "(this map)" : key);
            sb.append('=');

            if (maskedAttributeSet.contains(key)) {
                sb.append("[PROTECTED]");
            } else if (value == null) {
                sb.append("[]");
            } else {
                Iterator<V> it = value.iterator();
                sb.append('[');
                while (it.hasNext()) {
                    V v = it.next();
                    sb.append(v == this ? "(this map)" : v);
                    if (it.hasNext()) {
                        sb.append(',').append(' ');
                    }
                }
                sb.append(']');
            }

            if (i.hasNext()) {
                sb.append(',').append(' ');
            }
        }
        return sb.toString();
    }
}
