/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.metrics;

class MetricsAccessor {
    private static final ThreadLocal<RequestMetric> current = ThreadLocal.withInitial(() -> null);

    protected static RequestMetric getCurrent() {
        return current.get();
    }

    protected static void setCurrent(RequestMetric metric) {
        current.set(metric);
    }

    protected static void clear() {
        current.remove();
    }
}
