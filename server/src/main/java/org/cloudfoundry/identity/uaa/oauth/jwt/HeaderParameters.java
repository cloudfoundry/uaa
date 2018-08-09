package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.fasterxml.jackson.annotation.JsonProperty;

public class HeaderParameters {
    private static final String JWT = "JWT";
    @JsonProperty
    String alg;
    @JsonProperty
    String enc;
    @JsonProperty
    String kid;
    @JsonProperty
    String iv;
    @JsonProperty
    String typ;

    @SuppressWarnings("unused")
    HeaderParameters() {

    }

    HeaderParameters(String alg,
                     String enc,
                     String iv,
                     String kid,
                     String typ) {
        if (alg == null) {
            throw new IllegalArgumentException("alg is required");
        }
        this.alg = alg;
        this.enc = enc;
        this.iv = iv;
        this.kid = kid;
        this.typ = typ;
    }

    HeaderParameters(String alg,
                     String enc,
                     String iv,
                     String kid) {
        this(alg, enc, iv, kid, JWT);
    }

    public void setAlg(String alg) {
        if (alg == null) {
            throw new IllegalArgumentException("alg is required");
        }

        this.alg = alg;
    }

    public void setEnc(String enc) {
        this.enc = enc;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public void setTyp(String typ) {
        if (typ != null && !JWT.equalsIgnoreCase(typ)) {
            throw new IllegalArgumentException(String.format("typ is not \"%s\"", JWT));
        }
        this.typ = typ;
    }

    public String getEnc() {
        return enc;
    }

    public String getIv() {
        return iv;
    }

    public String getTyp() {
        return typ;
    }

    public String getKid() {
        return kid;
    }

    public String getAlg() {
        return alg;
    }
}
