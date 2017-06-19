package org.cloudfoundry.identity.uaa.scim.util;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import static org.springframework.util.StringUtils.hasText;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public final class ScimUtils {

    private static final Logger logger = LoggerFactory.getLogger(ScimUtils.class);

    private ScimUtils() {}

    /**
     * Generates a 1 hour expiring code.
     *
     * @param codeStore
     *                  the code store to use, must not be null
     * @param userId
     *                  the user id that will be included in the code's data, must not be null
     * @param email
     *                  the email that will be included in the code's data, must not be null
     * @param clientId
     *                  client id that will be included in the code's data, must not be null
     * @param redirectUri
     *                  the redirect uri that will be included in the code's data, may be null
     * @param intent
     *                  the intended purpose of the generated code
     * @return
     *                  the expiring code
     */
    public static ExpiringCode getExpiringCode(ExpiringCodeStore codeStore, String userId, String email, String clientId, String redirectUri, ExpiringCodeType intent) {
        Assert.notNull(codeStore);
        Assert.notNull(userId);
        Assert.notNull(email);
        Assert.notNull(intent);

        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", userId);
        codeData.put("email", email);
        codeData.put("client_id", clientId);
        if (redirectUri != null) {
            codeData.put("redirect_uri", redirectUri);
        }
        String codeDataString = JsonUtils.writeValueAsString(codeData);

        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + (60 * 60 * 1000)); // 1 hour
        return codeStore.generateCode(codeDataString, expiresAt, intent.name());
    }

    /**
     * Returns a verification URL that may be sent to a user.
     *
     * @param expiringCode
     *                      the expiring code to include on the URL, may be null
     * @return
     *          the verification URL
     */
    public static URL getVerificationURL(ExpiringCode expiringCode) {
        String url = "";
        try {
            url = UaaUrlUtils.getUaaUrl("/verify_user", true);

            if (expiringCode != null) {
                url += "?code=" + expiringCode.getCode();
            }

            return new URL(url);
        } catch (MalformedURLException mfue) {
            logger.error(String.format("Unexpected error creating user verification URL from %s", url), mfue);
        }
        throw new IllegalStateException();
    }

    public static void validate(final ScimUser user) throws InvalidScimResourceException {
        Pattern usernamePattern = Pattern.compile("[\\p{L}+0-9+\\-_.@'!]+");
        if (!hasText(user.getUserName())) {
            throw new InvalidScimResourceException("A username must be provided.");
        }
        if (OriginKeys.UAA.equals(user.getOrigin()) && !usernamePattern.matcher(user.getUserName()).matches()) {
            throw new InvalidScimResourceException("Username must match pattern: " + usernamePattern.pattern());
        }
        if (user.getEmails() == null || user.getEmails().size() != 1) {
            throw new InvalidScimResourceException("Exactly one email must be provided.");
        }
        for (ScimUser.Email email : user.getEmails()) {
            if (email == null || email.getValue() == null || email.getValue().isEmpty()) {
                throw new InvalidScimResourceException("An email must be provided.");
            }
        }
    }
}
