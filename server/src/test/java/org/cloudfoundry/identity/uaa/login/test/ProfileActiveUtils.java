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
package org.cloudfoundry.identity.uaa.login.test;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.test.annotation.ProfileValueSource;
import org.springframework.test.annotation.ProfileValueUtils;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class ProfileActiveUtils {
    public static boolean isTestEnabledInThisEnvironment(Class<?> testClass) {
        IfProfileActive ifProfileActive = AnnotationUtils.findAnnotation(testClass, IfProfileActive.class);
        UnlessProfileActive unlessProfileActive = AnnotationUtils.findAnnotation(testClass, UnlessProfileActive.class);
        return isTestEnabledInThisEnvironment(ProfileValueUtils.retrieveProfileValueSource(testClass), ifProfileActive, unlessProfileActive);
    }

    private static boolean isTestEnabledInThisEnvironment(ProfileValueSource profileValueSource, IfProfileActive ifProfileActive, UnlessProfileActive unlessProfileActive) {
        if (ifProfileActive == null && unlessProfileActive == null) {
            return true;
        }

        List<String> blacklist = getBlacklist(unlessProfileActive);
        Set<String> activeProfiles = StringUtils.commaDelimitedListToSet(profileValueSource.get("spring.profiles.active"));

        boolean enabled = true;
        if (ifProfileActive != null && StringUtils.hasText(ifProfileActive.value())) {
            enabled = activeProfiles.contains(ifProfileActive.value());
        }
        for (String profile : blacklist) {
            if (activeProfiles.contains(profile)) {
                enabled = false;
                continue;
            }
        }

        return enabled;
    }

    private static List<String> getBlacklist(UnlessProfileActive unlessProfileActive) {
        List<String> blacklist = new ArrayList<>();
        if (unlessProfileActive != null) {
            if (StringUtils.hasText(unlessProfileActive.value())) {
                blacklist.add(unlessProfileActive.value());
            }
            if (unlessProfileActive.values() != null) {
                blacklist.addAll(Arrays.asList(unlessProfileActive.values()));
            }
        }
        return blacklist;
    }
}
