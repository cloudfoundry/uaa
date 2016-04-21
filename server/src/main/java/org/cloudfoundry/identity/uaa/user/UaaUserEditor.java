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
package org.cloudfoundry.identity.uaa.user;

import java.beans.PropertyEditorSupport;
import java.util.Arrays;
import java.util.List;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.authority.AuthorityUtils;

public class UaaUserEditor extends PropertyEditorSupport {

    private static String SHORT_FORMAT = "unm|pwd{|comma-separated-authorities}";
    private static String LONG_FORMAT = "unm|pwd|email|fname|lname{|comma-separated-authorities}";
    private static List<String> SUPPORTED_FORMATS = Arrays.asList(SHORT_FORMAT, LONG_FORMAT);

    @Override
    public void setAsText(String text) throws IllegalArgumentException {
        String[] values = text.split("\\|");
        if (values.length < 2) {
            throw new IllegalArgumentException("Specify at least a username and password. Supported formats: "
                            + SUPPORTED_FORMATS);
        }

        String username = values[0], password = values[1];
        String email = username, firstName = null, lastName = null, origin = OriginKeys.UAA;
        String authorities = null;
        if (values.length > 2) {
            switch (values.length) {
                case 3:
                    authorities = values[2];
                    break;
                case 6:
                    email = values[2];
                    firstName = values[3];
                    lastName = values[4];
                    authorities = values[5];
                    break;
                case 5:
                    email = values[2];
                    firstName = values[3];
                    lastName = values[4];
                    break;
                case 7:
                    email = values[2];
                    firstName = values[3];
                    lastName = values[4];
                    authorities = values[5];
                    origin = values[6];
                    break;
                default:
                    throw new IllegalArgumentException("Supported formats: " + SUPPORTED_FORMATS);
            }
        }

        UaaUser user = new UaaUser(username, password, email, firstName, lastName, origin, IdentityZoneHolder.get().getId());
        if (authorities != null) {
            user = user.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
        }
        super.setValue(user);
    }

}
