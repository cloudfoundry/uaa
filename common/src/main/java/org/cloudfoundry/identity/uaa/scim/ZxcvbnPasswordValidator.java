/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.password.PasswordScoreCalculator;
import org.cloudfoundry.identity.uaa.password.PasswordScore;

/**
 * A PasswordValidator that uses the Zxcvbn Scala library to validate passwords
 * @author vidya
 */
public class ZxcvbnPasswordValidator implements PasswordValidator {

    private PasswordScoreCalculator scoreCalculator;

    public void setScoreCalculator(PasswordScoreCalculator scoreCalculator) {
        this.scoreCalculator = scoreCalculator;
    }

    @Override
    public void validate(String password, ScimUser user) {
        PasswordScore score = scoreCalculator.computeScore(password);
        if (!score.isAcceptable()) {
            throw new InvalidPasswordException(String.format("Insufficient password strength: %d", score.getScore()));
        }

    }
}
