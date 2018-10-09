package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import static com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonIgnoreProperties(ignoreUnknown = true)
public class HeaderParameters {
    private static final String JWT = "JWT";
    @JsonProperty
    String alg;
    @JsonProperty
    @JsonInclude(Include.NON_NULL)
    String enc;
    @JsonProperty
    @JsonInclude(Include.NON_NULL)
    String iv;
    @JsonProperty
    String jku;
    @JsonProperty
    String kid;
    @JsonProperty
    String typ;

    public Object cty;
    public Object iss;
    public Object aud;
    public Object sub;

    @SuppressWarnings("unused")
    HeaderParameters() {

    }

    HeaderParameters(String alg,
                     String enc,
                     String iv,
                     String kid,
                     String jku,
                     String typ) {
        if (alg == null) {
            throw new IllegalArgumentException("alg is required");
        }
        this.alg = alg;
        this.enc = enc;
        this.iv = iv;
        this.jku = jku;
        this.kid = kid;
        this.typ = typ;
    }

    HeaderParameters(String alg,
                     String enc,
                     String iv,
                     String kid,
                     String jku) {
        this(alg, enc, iv, kid, jku, JWT);
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        if (alg == null) {
            throw new IllegalArgumentException("alg is required");
        }

        this.alg = alg;
    }

    public String getEnc() {
        return enc;
    }

    public void setEnc(String enc) {
        this.enc = enc;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getIv() {
        return iv;
    }

    public String getJku() {
        return jku;
    }

    public void setJku(String jku) {
        this.jku = jku;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getKid() {
        return kid;
    }

    public void setTyp(String typ) {
        if (typ != null && !JWT.equalsIgnoreCase(typ)) {
            throw new IllegalArgumentException(String.format("typ is not \"%s\"", JWT));
        }
        this.typ = typ;
    }

    public String getTyp() {
        return typ;
    }

}
