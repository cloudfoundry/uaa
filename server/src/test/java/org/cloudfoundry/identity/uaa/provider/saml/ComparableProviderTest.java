package org.cloudfoundry.identity.uaa.provider.saml; /*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

import org.junit.Test;
import org.opensaml.xml.XMLObject;

import static org.junit.Assert.*;

public class ComparableProviderTest {

    class ComparableProviderImpl implements ComparableProvider{
        private String alias;
        private String zoneId;

        @Override
        public String getAlias() {
            return alias;
        }

        @Override
        public String getZoneId() {
            return zoneId;
        }

        @Override
        public XMLObject doGetMetadata() {
            return null;
        }

        @Override
        public byte[] fetchMetadata() {
            return new byte[0];
        }

        public ComparableProviderImpl setAlias(String alias) {
            this.alias = alias;
            return this;
        }

        public ComparableProviderImpl setZoneId(String zoneId) {
            this.zoneId = zoneId;
            return this;
        }

    }

    @Test
    public void testCompareTo(){
        ComparableProviderImpl comparableProviderThis = new ComparableProviderImpl();
        ComparableProviderImpl comparableProviderThat = new ComparableProviderImpl();

        comparableProviderThis.setAlias(null).setZoneId(null);
        comparableProviderThat.setAlias("alias").setZoneId("zone");
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) < 0);

        comparableProviderThat.setAlias("alias").setZoneId(null);
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) < 0);

        comparableProviderThat.setAlias(null).setZoneId("zone");
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) < 0);

        comparableProviderThat.setAlias(null).setZoneId(null);
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) == 0);


        comparableProviderThis.setAlias(null).setZoneId("zone");
        comparableProviderThat.setAlias("alias").setZoneId("zone");
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) < 0);

        comparableProviderThat.setAlias("alias").setZoneId(null);
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) < 0);

        comparableProviderThat.setAlias(null).setZoneId("zone");
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) == 0);

        comparableProviderThat.setAlias(null).setZoneId(null);
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) > 0);


        comparableProviderThis.setAlias("alias").setZoneId(null);
        comparableProviderThat.setAlias("alias").setZoneId("zone");
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) < 0);

        comparableProviderThat.setAlias("alias").setZoneId(null);
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) == 0);

        comparableProviderThat.setAlias(null).setZoneId("zone");
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) > 0);

        comparableProviderThat.setAlias(null).setZoneId(null);
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) > 0);

        comparableProviderThis.setAlias("alias").setZoneId("zone");
        comparableProviderThat.setAlias("alias").setZoneId("zone");
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) == 0);

        comparableProviderThat.setAlias("alias").setZoneId(null);
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) > 0);

        comparableProviderThat.setAlias(null).setZoneId("zone");
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) > 0);

        comparableProviderThat.setAlias(null).setZoneId(null);
        assertTrue(comparableProviderThis.compareTo(comparableProviderThat) > 0);
    }

    @Test
    public void testGetHashCode() {
        ComparableProviderImpl comparableProvider1 = new ComparableProviderImpl();
        ComparableProviderImpl comparableProvider2 = new ComparableProviderImpl();
        comparableProvider1.setAlias(null).setZoneId(null);

        assertEquals(0, comparableProvider1.getHashCode());

        comparableProvider1.setAlias(null).setZoneId("zone");
        comparableProvider2.setAlias(null).setZoneId("zone");
        assertEquals(comparableProvider1.getHashCode(), comparableProvider2.getHashCode());

        comparableProvider1.setAlias("alias").setZoneId(null);
        comparableProvider2.setAlias("alias").setZoneId(null);
        assertEquals(comparableProvider1.getHashCode(), comparableProvider2.getHashCode());

        comparableProvider1.setAlias("alias").setZoneId(null);
        comparableProvider2.setAlias(null).setZoneId("zone");
        assertNotEquals(comparableProvider1.getHashCode(), comparableProvider2.getHashCode());
    }
}