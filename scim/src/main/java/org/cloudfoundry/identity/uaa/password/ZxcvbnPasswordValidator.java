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

import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordScore;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordScoreCalculator;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;

/**
 * A PasswordValidator that uses the Zxcvbn Scala library to validate passwords
 * 
 * @author vidya
 */
public class ZxcvbnPasswordValidator implements PasswordValidator {

    private PasswordScoreCalculator scoreCalculator;

    public void setScoreCalculator(PasswordScoreCalculator scoreCalculator) {
        this.scoreCalculator = scoreCalculator;
    }

    @Override
    public Void validate(String password) {
        PasswordScore score = scoreCalculator.computeScore(password);
        if (score.getScore() < score.getRequiredScore()) {
            throw new InvalidPasswordException(String.format("Insufficient password strength: %d", score.getScore()));
        }

        return null;
    }
}
