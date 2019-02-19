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
 *
 * <p>
 * This Map implementation is generally not thread-safe. It is primarily
 * designed for data structures exposed from request objects, for use in a
 * single thread only.
 *
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

    private static final long serialVersionUID = 3801124242820219132L;

    private final Map<K, List<V>> targetMap;

    private final Set<K> maskedAttributeSet = new HashSet<K>();

    /**
     * Create a new LinkedMultiValueMap that wraps a {@link java.util.LinkedHashMap}.
     */
    public LinkedMaskingMultiValueMap() {
        this.targetMap = new LinkedHashMap<K, List<V>>();
    }

    public LinkedMaskingMultiValueMap(K maskedAttribute) {
        this.targetMap = new LinkedHashMap<K, List<V>>();
        this.maskedAttributeSet.add(maskedAttribute);
    }

    public LinkedMaskingMultiValueMap(K... maskedAttribute) {
        this.targetMap = new LinkedHashMap<K, List<V>>();
        this.maskedAttributeSet.addAll(Arrays.asList(maskedAttribute));
    }

    /**
     * Create a new LinkedMultiValueMap that wraps a {@link java.util.LinkedHashMap}.
     */
    public LinkedMaskingMultiValueMap(Set<K> maskedAttributes) {
        this.targetMap = new LinkedHashMap<K, List<V>>();
        this.maskedAttributeSet.addAll(maskedAttributes);
    }

    /**
     * Create a new LinkedMultiValueMap that wraps a {@link java.util.LinkedHashMap} with
     * the given initial capacity.
     *
     * @param initialCapacity the initial capacity
     */
    public LinkedMaskingMultiValueMap(int initialCapacity) {
        this.targetMap = new LinkedHashMap<K, List<V>>(initialCapacity);
    }

    /**
     * Copy constructor: Create a new LinkedMultiValueMap with the same mappings
     * as the specified Map.
     *
     * @param otherMap the Map whose mappings are to be placed in this Map
     */
    public LinkedMaskingMultiValueMap(Map<K, List<V>> otherMap) {
        this.targetMap = new LinkedHashMap<K, List<V>>(otherMap);
    }

    // masked attributes

    // MultiValueMap implementation

    @Override
    public void add(K key, V value) {
        List<V> values = this.targetMap.get(key);
        if (values == null) {
            values = new LinkedList<V>();
            this.targetMap.put(key, values);
        }
        values.add(value);
    }

    @Override
    public V getFirst(K key) {
        List<V> values = this.targetMap.get(key);
        return (values != null ? values.get(0) : null);
    }

    @Override
    public void set(K key, V value) {
        List<V> values = new LinkedList<V>();
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
        LinkedHashMap<K, V> singleValueMap = new LinkedHashMap<K, V>(this.targetMap.size());
        for (Entry<K, List<V>> entry : targetMap.entrySet()) {
            singleValueMap.put(entry.getKey(), entry.getValue().get(0));
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
        Iterator<Entry<K, List<V>>> i = entrySet().iterator();
        while (i.hasNext()) {
            int keyHash = 1;
            Entry<K, List<V>> entry = i.next();
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

            h += (keyHash ^ valueHash);
        }
        return h;
    }

    @Override
    public String toString() {
        Iterator<Entry<K, List<V>>> i = targetMap.entrySet().iterator();
        if (!i.hasNext())
            return "{}";

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
