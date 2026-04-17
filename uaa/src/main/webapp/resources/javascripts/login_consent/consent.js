document.addEventListener('DOMContentLoaded', function () {
    'use strict';

    const COOKIE_NAME = 'UAA-Login-Consent';

    // Cookie utility functions
    function getCookie(name) {
        const value = '; ' + document.cookie;
        const parts = value.split('; ' + name + '=');
        if (parts.length === 2) {
            return parts.pop().split(';').shift();
        }
        return null;
    }

    function setCookie(name, value, maxAge) {
        // Use current path so cookie works with any context path (e.g. /login or /uaa/login)
        const path = window.location.pathname || '/login';
        let cookie = name + '=' + value + '; path=' + path + '; SameSite=Strict';
        if (window.location.protocol === 'https:') {
            cookie += '; Secure';
        }
        if (maxAge > 0) {
            cookie += '; max-age=' + maxAge;
        }
        document.cookie = cookie;
    }

    function shouldShowConsent() {
        const modal = document.getElementById('loginConsentModal');
        if (!modal) {
            return false;
        }

        const consentDuration = parseInt(modal.getAttribute("data-consent-duration"), 10);
        // Always show if the duration is 0
        if (consentDuration === 0) {
            return true;
        }

        const cookieValue = getCookie(COOKIE_NAME);
        if (!cookieValue) {
            return true;
        }

        // Cookie format: hash:timestamp
        const parts = cookieValue.split(':');
        if (parts.length !== 2) {
            return true;
        }

        const consentHash = modal.getAttribute("data-consent-hash");
        const storedHash = parts[0];
        const timestamp = parseInt(parts[1], 10);

        // Check if hash matches (consent text hasn't changed)
        if (storedHash !== consentHash) {
            return true;
        }

        // Check if the cookie has expired
        const now = Math.floor(Date.now() / 1000);
        return consentDuration > 0 && (now - timestamp) > consentDuration;
    }

    function showModal() {
        const modal = document.getElementById('loginConsentModal');
        if (modal) {
            modal.style.display = 'flex';
            modal.setAttribute('aria-hidden', 'false');

            // Trap focus in modal
            const acceptButton = document.getElementById('consentAcceptButton');
            if (acceptButton) {
                acceptButton.focus();
            }

            // Disable page interaction
            document.body.style.overflow = 'hidden';
        }
    }

    function hideModal() {
        const modal = document.getElementById('loginConsentModal');
        if (modal) {
            modal.style.display = 'none';
            modal.setAttribute('aria-hidden', 'true');
            document.body.style.overflow = '';
        }
    }

    function acceptConsent() {
        const modal = document.getElementById('loginConsentModal');
        const consentDuration = parseInt(modal.getAttribute("data-consent-duration"), 10);
        const consentHash = modal.getAttribute("data-consent-hash");

        if (consentDuration > 0) {
            const timestamp = Math.floor(Date.now() / 1000);
            const cookieValue = consentHash + ':' + timestamp;
            setCookie(COOKIE_NAME, cookieValue, consentDuration);
        }
        hideModal();
    }

    // Initialize on page load
    if (shouldShowConsent()) {
        // Set up event listeners
        const acceptButton = document.getElementById('consentAcceptButton');
        if (acceptButton) {
            acceptButton.addEventListener('click', acceptConsent);
        }

        const cancelButton = document.getElementById('consentCancelButton');
        if (cancelButton) {
            cancelButton.addEventListener('click', function () {
                // Cancel just closes modal, will show again on refresh
                hideModal();
                // Show again after a short delay to prevent user from proceeding
                setTimeout(showModal, 100);
            });
        }

        // Prevent closing modal by clicking outside
        const modal = document.getElementById('loginConsentModal');
        if (modal) {
            modal.addEventListener('click', function (e) {
                if (e.target === modal) {
                    // Don't allow closing by clicking overlay
                    e.preventDefault();
                }
            });
        }

        // Prevent ESC key from closing modal
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && modal && modal.style.display === 'flex') {
                e.preventDefault();
            }
        });

        showModal();

    }
});