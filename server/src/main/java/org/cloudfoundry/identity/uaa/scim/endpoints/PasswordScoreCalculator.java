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

package org.cloudfoundry.identity.uaa.scim.endpoints;

/**
 * Computes a strength/score for a given password
 * 
 * @author vidya
 */
public interface PasswordScoreCalculator {

    /**
     * @param password the trial password
     * @param userData user-specific data which should not be in the password.
     * @return the score computed for the password
     */
    PasswordScore computeScore(String password, String... userData);
}
