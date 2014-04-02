/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.password;

import static szxcvbn.ZxcvbnHelper.zxcvbn;

import java.util.Arrays;

import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordScore;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordScoreCalculator;

/**
 * A PasswordScoreCalculator that uses the Zxcvbn scala library to compute the
 * strength of a given password.
 * Uses a configurable 'requiredScore' property to flag a password as
 * (un)acceptable.
 * 
 * @author vidya
 */
public class ZxcvbnPasswordScoreCalculator implements PasswordScoreCalculator {
    private final Integer requiredScore;

    public ZxcvbnPasswordScoreCalculator(int requiredScore) {
        this.requiredScore = requiredScore;
    }

    @Override
    public PasswordScore computeScore(String password, String... userData) {
        int score = zxcvbn(password, Arrays.asList(userData)).score();
        return new PasswordScore(score, requiredScore);
    }
}
