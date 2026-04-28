package org.cloudfoundry.identity.uaa.approval.impl;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import tools.jackson.databind.ValueDeserializer;

import java.util.Date;

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
public class ApprovalsJsonDeserializer extends ValueDeserializer<Approval> {

    @Override
    public Approval deserialize(JsonParser jp, DeserializationContext ctxt) {
        Approval approval = new Approval();
        while (jp.nextToken() != JsonToken.END_OBJECT) {
            if (jp.currentToken() == JsonToken.PROPERTY_NAME) {
                String fieldName = jp.currentName();
                jp.nextToken();
                if ("userId".equalsIgnoreCase(fieldName)) {
                    approval.setUserId(jp.readValueAs(String.class));
                } else if ("clientId".equalsIgnoreCase(fieldName)) {
                    approval.setClientId(jp.readValueAs(String.class));
                } else if ("scope".equalsIgnoreCase(fieldName)) {
                    approval.setScope(jp.readValueAs(String.class));
                } else if ("status".equalsIgnoreCase(fieldName)) {
                    approval.setStatus(jp.readValueAs(ApprovalStatus.class));
                } else if ("expiresAt".equalsIgnoreCase(fieldName)) {
                    approval.setExpiresAt(jp.readValueAs(Date.class));
                } else if ("lastUpdatedAt".equalsIgnoreCase(fieldName)) {
                    approval.setLastUpdatedAt(jp.readValueAs(Date.class));
                }
            }
        }
        return approval;
    }
}
