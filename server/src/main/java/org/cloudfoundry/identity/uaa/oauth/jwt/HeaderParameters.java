package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

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
    @JsonProperty
    @JsonInclude(Include.NON_NULL)
    String cty;
    @JsonProperty
    @JsonInclude(Include.NON_NULL)
    String jwk;
    @JsonProperty
    @JsonInclude(Include.NON_NULL)
    String x5u;
    @JsonProperty
    @JsonInclude(Include.NON_NULL)
    String x5c;
    @JsonProperty
    @JsonInclude(Include.NON_NULL)
    String x5t;
    @JsonProperty(value = "x5t#S256")
    @JsonInclude(Include.NON_NULL)
    String x5tS256;
    @JsonProperty
    @JsonInclude(Include.NON_NULL)
    List<String> crit;

    @SuppressWarnings("unused")
    HeaderParameters() {

    }

    HeaderParameters(String alg,
                     String kid,
                     String jku) {
        if (alg == null) {
            throw new IllegalArgumentException("alg is required");
        }
        this.alg = alg;
        this.jku = jku;
        this.kid = kid;
        this.typ = JWT;
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

    public String getJku() {
        return jku;
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
