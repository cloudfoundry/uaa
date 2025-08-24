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
package org.cloudfoundry.identity.uaa.audit;

/**
 * Allows audit events to be classified by type.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
public enum AuditEventType {

    // Do not change the code values, as these are used in the database.
    UserAuthenticationSuccess(0),
    UserAuthenticationFailure(1),
    UserNotFound(2),
    PasswordChangeSuccess(3),
    PrincipalAuthenticationSuccess(4),
    PrincipalAuthenticationFailure(5),
    PrincipalNotFound(6),
    PasswordChangeFailure(7),
    SecretChangeSuccess(8),
    SecretChangeFailure(9),
    ClientCreateSuccess(10),
    ClientUpdateSuccess(11),
    ClientDeleteSuccess(12),
    ClientApprovalsDeleted(13),
    ClientAuthenticationSuccess(14),
    ClientAuthenticationFailure(15),
    ApprovalModifiedEvent(16),
    TokenIssuedEvent(17),
    UserCreatedEvent(18),
    UserModifiedEvent(19),
    UserDeletedEvent(20),
    UserVerifiedEvent(21),
    PasswordResetRequest(22),
    GroupCreatedEvent(23),
    GroupModifiedEvent(24),
    GroupDeletedEvent(25),
    EmailChangedEvent(26),
    UnverifiedUserAuthentication(27),
    IdentityProviderCreatedEvent(28),
    IdentityProviderModifiedEvent(29),
    IdentityZoneCreatedEvent(30),
    IdentityZoneModifiedEvent(31),
    EntityDeletedEvent(32),
    ServiceProviderCreatedEvent(33),
    ServiceProviderModifiedEvent(34),
    UserAccountUnlockedEvent(35),
    TokenRevocationEvent(36),
    IdentityProviderAuthenticationSuccess(37),
    IdentityProviderAuthenticationFailure(38),
    MfaAuthenticationSuccess(39), // This is unused, as MFA is feature is removed, but removing this event results in [this test failure](https://github.com/cloudfoundry/uaa/blob/8a4ca068aa6f4faeb3e83765ead5900ceb159121/server/src/test/java/org/cloudfoundry/identity/uaa/audit/AuditEventTypeTests.java); fixing the test would require changing the event code number, which [this comment](https://github.com/cloudfoundry/uaa/blob/8a4ca068aa6f4faeb3e83765ead5900ceb159121/server/src/main/java/org/cloudfoundry/identity/uaa/audit/AuditEventType.java#L23) says we cannot. So leaving this unused event here for now.
    MfaAuthenticationFailure(40), // This is unused, as MFA is feature is removed, but removing this event results in [this test failure](https://github.com/cloudfoundry/uaa/blob/8a4ca068aa6f4faeb3e83765ead5900ceb159121/server/src/test/java/org/cloudfoundry/identity/uaa/audit/AuditEventTypeTests.java); fixing the test would require changing the event code number, which [this comment](https://github.com/cloudfoundry/uaa/blob/8a4ca068aa6f4faeb3e83765ead5900ceb159121/server/src/main/java/org/cloudfoundry/identity/uaa/audit/AuditEventType.java#L23) says we cannot. So leaving this unused event here for now.
    ClientJwtChangeSuccess(41),
    ClientJwtChangeFailure(42);

    private final int code;

    AuditEventType(int code) {
        this.code = code;
    }

    public static AuditEventType fromCode(int code) {
        for (AuditEventType a : AuditEventType.values()) {
            if (a.getCode() == code) {
                return a;
            }
        }
        throw new IllegalArgumentException("No event type with code " + code + " exists");
    }

    public int getCode() {
        return code;
    }
}
