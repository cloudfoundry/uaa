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
package org.cloudfoundry.identity.uaa.mock;

import org.junit.ClassRule;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.stream.Collectors;

@RunWith(UaaJunitSuiteRunner.class)
public class DefaultDocsTestSuite extends DefaultConfigurationTestSuite {

    @ClassRule
    public static InjectedMockContextTest.SkipWhenNotRunningInSuiteRule skip = new InjectedMockContextTest.SkipWhenNotRunningInSuiteRule();


    public static Class<?>[] suiteClasses() {
        Class<?>[] result = UaaJunitSuiteRunner.allSuiteClasses();
        Arrays.sort(result, (o1, o2) -> o1.getSimpleName().compareTo(o2.getSimpleName()));
        return Arrays.stream(result)
            .filter(k -> k.getSimpleName().endsWith("Docs"))
            .collect(Collectors.toList())
            .toArray(new Class[0]);
    }

    public DefaultDocsTestSuite() {
    }

}
