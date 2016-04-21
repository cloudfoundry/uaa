/*******************************************************************************
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

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

public class UaaPagingUtilsTests {

    List<String> list;

    @Before
    public void createList() {
        list = new ArrayList<String>();
        list.add("one");
        list.add("two");
        list.add("three");
        list.add("four");
    }

    @Test
    public void testPagingSubListHighCount() {
        List<String> result = UaaPagingUtils.subList(list, 1, 100);
        assertEquals(4, result.size());
        assertEquals("one", result.get(0));
        assertEquals("four", result.get(3));
    }

    @Test
    public void testPagingSubListLowCount() {
        List<String> result = UaaPagingUtils.subList(list, 1, 2);
        assertEquals(2, result.size());
        assertEquals("one", result.get(0));
        assertEquals("two", result.get(1));
    }

    @Test
    public void testPagingSubListEqualCount() {
        List<String> result = UaaPagingUtils.subList(list, 1, 4);
        assertEquals(4, result.size());
        assertEquals("one", result.get(0));
        assertEquals("four", result.get(3));

    }

    @Test
    public void testPagingSubListOneCount() {
        List<String> result = UaaPagingUtils.subList(list, 1, 1);
        assertEquals(1, result.size());
        assertEquals("one", result.get(0));
    }

    @Test
    public void testPagingSubListPage() {
        List<String> result = UaaPagingUtils.subList(list, 3, 2);
        assertEquals(2, result.size());
        assertEquals("three", result.get(0));
        assertEquals("four", result.get(1));
    }

    @Test
    public void testPagingSubListPageHighCount() {
        List<String> result = UaaPagingUtils.subList(list, 2, 100);
        assertEquals(3, result.size());
        assertEquals("two", result.get(0));
        assertEquals("four", result.get(2));
    }

}
