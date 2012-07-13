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

package org.cloudfoundry.identity.uaa.password;

import org.codehaus.jackson.map.annotate.JsonSerialize;

@JsonSerialize (include = JsonSerialize.Inclusion.NON_NULL)
public class PasswordScore {
    private String password;
    private int score;
    private boolean isAcceptable;

    public PasswordScore(String password, int score, boolean acceptable) {
        this.password = password;
        this.score = score;
        isAcceptable = acceptable;
    }

    public boolean isAcceptable() {
        return isAcceptable;
    }

    public void setAcceptable(boolean acceptable) {
        isAcceptable = acceptable;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getScore() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }
}
