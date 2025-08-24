package org.cloudfoundry.identity.uaa.web.beans;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.RequestRejectedHandler;

import java.io.IOException;

public class UaaRequestRejectedHandler implements RequestRejectedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, RequestRejectedException requestRejectedException)
            throws IOException, ServletException {
            request.setAttribute(RequestDispatcher.ERROR_EXCEPTION, requestRejectedException);
            request.setAttribute(RequestDispatcher.ERROR_REQUEST_URI, request.getRequestURI());
            request.getRequestDispatcher("/rejected").forward(request, response);
    }
}
