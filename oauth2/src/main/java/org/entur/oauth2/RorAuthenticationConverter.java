package org.entur.oauth2;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

/**
 * Authentication converter that transforms the JWT claims into Spring Security Granted Authorities.
 */
public class RorAuthenticationConverter extends JwtAuthenticationConverter {

    public RorAuthenticationConverter() {
        this.setJwtGrantedAuthoritiesConverter(new RorGrantedAuthoritiesConverter());
    }
}
