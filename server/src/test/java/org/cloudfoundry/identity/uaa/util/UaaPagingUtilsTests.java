/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class UaaPagingUtilsTests {

    List<String> list;

    @BeforeEach
    void createList() {
        list = new ArrayList<>();
        list.add("one");
        list.add("two");
        list.add("three");
        list.add("four");
    }

    @Test
    void pagingSubListHighCount() {
        List<String> result = UaaPagingUtils.subList(list, 1, 100);
        assertThat(result).hasSize(4);
        assertThat(result.getFirst()).isEqualTo("one");
        assertThat(result.get(3)).isEqualTo("four");
    }

    @Test
    void pagingSubListLowCount() {
        List<String> result = UaaPagingUtils.subList(list, 1, 2);
        assertThat(result).hasSize(2);
        assertThat(result.getFirst()).isEqualTo("one");
        assertThat(result.get(1)).isEqualTo("two");
    }

    @Test
    void pagingSubListEqualCount() {
        List<String> result = UaaPagingUtils.subList(list, 1, 4);
        assertThat(result).hasSize(4);
        assertThat(result.getFirst()).isEqualTo("one");
        assertThat(result.get(3)).isEqualTo("four");

    }

    @Test
    void pagingSubListOneCount() {
        List<String> result = UaaPagingUtils.subList(list, 1, 1);
        assertThat(result).hasSize(1);
        assertThat(result.getFirst()).isEqualTo("one");
    }

    @Test
    void pagingSubListPage() {
        List<String> result = UaaPagingUtils.subList(list, 3, 2);
        assertThat(result).hasSize(2);
        assertThat(result.getFirst()).isEqualTo("three");
        assertThat(result.get(1)).isEqualTo("four");
    }

    @Test
    void pagingSubListPageHighCount() {
        List<String> result = UaaPagingUtils.subList(list, 2, 100);
        assertThat(result).hasSize(3);
        assertThat(result.getFirst()).isEqualTo("two");
        assertThat(result.get(2)).isEqualTo("four");
    }

}
