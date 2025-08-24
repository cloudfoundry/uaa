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
package org.cloudfoundry.identity.uaa.scim.validate;

import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;

/**
 * Validates password values when creating users or changing passwords.
 * 
 * Should implement the password policy defined for the system.
 * User interfaces should obviously also implement the same policy.
 * 
 * @author Luke Taylor
 */
public interface PasswordValidator {
    /**
     * Validates the password as to whether it is valid for a specific user.
     *  @param password the trial password
     *
     */
    void validate(String password) throws InvalidPasswordException;
}
