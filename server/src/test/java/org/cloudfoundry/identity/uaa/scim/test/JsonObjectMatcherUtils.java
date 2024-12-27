/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.scim.test;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.util.Objects;

/**
 * A {@link org.hamcrest.Matcher} that matches the {@link org.json.JSONObject} represented by the given {@link String}
 * in an order-insensitive way against an expected {@link org.json.JSONObject}.
 */
public class JsonObjectMatcherUtils extends BaseMatcher<String> {

    private final JSONObject expected;

    public JsonObjectMatcherUtils(JSONObject expected) {
        this.expected = expected;
    }

    public static Matcher<? super String> matchesJsonObject(JSONObject expected) {
        return new JsonObjectMatcherUtils(expected);
    }

    @Override
    public boolean matches(Object item) {

        if (!(item instanceof String)) {
            return false;
        }

        if (this.expected == null && "null".equals(item)) {
            return true;
        }

        JSONObject actual = null;
        try {
            actual = new JSONObject(new JSONTokener(item.toString()));
        } catch (JSONException e) {
            return false;
        }

        if (this.expected.length() != actual.length()) {
            return false;
        }

        JSONArray names = actual.names();
        for (int i = 0, len = names.length(); i < len; i++) {

            try {
                String name = names.getString(i);
                if (!Objects.equals(expected.get(name), actual.get(name))) {
                    return false;
                }
            } catch (JSONException e) {
                return false;
            }
        }

        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendValue(expected);
    }
}
