package org.cloudfoundry.identity.uaa.security;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.Serializable;

import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;

public class SavedRequestAwareAuthenticationDetails extends WebAuthenticationDetails implements Serializable {

    private static final long serialVersionUID = 3801124242820219132L;

    private Object savedRequest;

    public SavedRequestAwareAuthenticationDetails(HttpServletRequest request) {
        super(request);

        HttpSession session = request.getSession(false);
        if (session != null) {
            savedRequest = session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        }
    }

    public Object getSavedRequest() {
        return savedRequest;
    }

    public void setSavedRequest(Object savedRequest) {
        this.savedRequest = savedRequest;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SavedRequestAwareAuthenticationDetails)) return false;
        if (!super.equals(o)) return false;

        SavedRequestAwareAuthenticationDetails that = (SavedRequestAwareAuthenticationDetails) o;

        if (savedRequest != null ? !savedRequest.equals(that.savedRequest) : that.savedRequest != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (savedRequest != null ? savedRequest.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString()).append(": ");
        sb.append("SavedRequest: ").append(this.getSavedRequest());

        return sb.toString();
    }
}
