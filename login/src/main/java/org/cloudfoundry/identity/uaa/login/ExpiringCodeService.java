package org.cloudfoundry.identity.uaa.login;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public interface ExpiringCodeService {
    String generateCode(Object data, int expiryTime, TimeUnit timeUnit) throws IOException;
    <T> T verifyCode(Class<T> clazz, String code) throws CodeNotFoundException, IOException;
    Map<String, String> verifyCode(String code) throws CodeNotFoundException, IOException;
    
    public class CodeNotFoundException extends Exception {

        public CodeNotFoundException() {
            super();
        }


        public CodeNotFoundException(String message, Throwable cause) {
            super(message, cause);
        }

        public CodeNotFoundException(String message) {
            super(message);
        }

        public CodeNotFoundException(Throwable cause) {
            super(cause);
        }

        /**
         * 
         */
        private static final long serialVersionUID = -7579875965452686646L;
        
    }


}
