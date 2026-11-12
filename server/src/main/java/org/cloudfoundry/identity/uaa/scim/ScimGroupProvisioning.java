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
package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.resources.Queryable;
import org.cloudfoundry.identity.uaa.resources.ResourceManager;

import java.util.List;

public interface ScimGroupProvisioning extends ResourceManager<ScimGroup>, Queryable<ScimGroup> {
    /** Returns a lazy list with a total size, fetching at most maxPageSize rows per database page. */
    List<ScimGroup> query(String filter, String sortBy, boolean ascending, String zoneId, int maxPageSize);

    ScimGroup createOrGet(ScimGroup group, String zoneId);

    ScimGroup getByName(String displayName, String zoneId);
}
