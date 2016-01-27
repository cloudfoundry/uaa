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
package org.cloudfoundry.identity.uaa.login.test;

import org.junit.runner.Description;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.InitializationError;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

public class LoginServerClassRunner extends SpringJUnit4ClassRunner {
    public LoginServerClassRunner(Class<?> clazz) throws InitializationError {
        super(clazz);
    }

    @Override
    public Description getDescription() {
        if (!ProfileActiveUtils.isTestEnabledInThisEnvironment(getTestClass().getJavaClass())) {
            return Description.createSuiteDescription(getTestClass().getJavaClass());
        }
        return super.getDescription();
    }

    @Override
    public void run(RunNotifier notifier) {
        if (!ProfileActiveUtils.isTestEnabledInThisEnvironment(getTestClass().getJavaClass())) {
            notifier.fireTestIgnored(getDescription());
            return;
        }
        super.run(notifier);
    }

    @Override
    protected boolean isTestMethodIgnored(FrameworkMethod frameworkMethod) {
        return super.isTestMethodIgnored(frameworkMethod) || !ProfileActiveUtils.isTestEnabledInThisEnvironment(getTestClass().getJavaClass());
    }
}
