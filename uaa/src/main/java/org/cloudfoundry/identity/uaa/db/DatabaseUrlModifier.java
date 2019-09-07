/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.db;

public class DatabaseUrlModifier {

    private final Vendor databaseType;
    private final String url;
    private int connectTimeoutSeconds = 10;

    public DatabaseUrlModifier(Vendor databaseType, String url) {
        if (databaseType==null) {
            throw new NullPointerException();
        }

        this.databaseType = databaseType;
        this.url = url;
    }

    public int getConnectTimeoutSeconds() {
        return connectTimeoutSeconds;
    }

    public void setConnectTimeoutSeconds(int connectTimeoutSeconds) {
        this.connectTimeoutSeconds = connectTimeoutSeconds;
    }

    public Vendor getDatabaseType() {
        return databaseType;
    }

    public String getUrl() {
        StringBuilder result = new StringBuilder(url);
        switch (getDatabaseType()) {
            case mysql : {
                appendParameter(result, "connectTimeout", getConnectTimeoutSeconds()*1000);
                break;
            }
            case postgresql : {
                appendParameter(result, "connectTimeout", getConnectTimeoutSeconds());
                break;
            }
            case hsqldb : {break;}
            default : throw new IllegalStateException("Unrecognized database: "+ databaseType);
        }
        return result.toString();
    }

    private void appendParameter(StringBuilder result, String name, Object value) {
        if (result.indexOf("?") > 0) {
            result.append("&");
        } else {
            result.append("?");
        }
        result.append(name);
        result.append("=");
        result.append(value.toString());
    }
}
