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
