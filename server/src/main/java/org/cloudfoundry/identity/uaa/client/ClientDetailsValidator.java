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

package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

public interface ClientDetailsValidator {

    /**
     *
     * @return Returns the configured client secret validator
     */
    ClientSecretValidator getClientSecretValidator();

    /**
     *
     * @param clientDetails
     * @param mode represents the request {@link Mode}
     * @return A validated and possibly modified client
     */
    ClientDetails validate(ClientDetails clientDetails, Mode mode) throws InvalidClientDetailsException;

    enum Mode {
        CREATE, MODIFY, DELETE
    }

}