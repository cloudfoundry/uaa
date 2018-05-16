package org.cloudfoundry.identity.uaa.zone;

public class Consent {
    private String text;
    private String link;

    public Consent() {
    }

    public Consent(String text, String link) {
        this.text = text;
        this.link = link;
    }

    public String getText() {
        return text;
    }

    public String getLink() {
        return link;
    }

    public void setText(String text) {
        this.text = text;
    }

    public void setLink(String link) {
        this.link = link;
    }
}
