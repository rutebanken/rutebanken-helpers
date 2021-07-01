package org.entur.oauth2;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

public class RoRJwtDecoderBuilder {

    private String issuer;
    private String audience;
    private String auth0ClaimNamespace;

    public RoRJwtDecoderBuilder withIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public RoRJwtDecoderBuilder withAudience(String audience) {
        this.audience = audience;
        return this;
    }

    public RoRJwtDecoderBuilder withAuth0ClaimNamespace(String auth0ClaimNamespace) {
        this.auth0ClaimNamespace = auth0ClaimNamespace;
        return this;
    }

    public JwtDecoder build() {
        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(issuer);

        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(audience);
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);
        jwtDecoder.setJwtValidator(withAudience);
        jwtDecoder.setClaimSetConverter(new RorAuth0RolesClaimAdapter(auth0ClaimNamespace));
        return jwtDecoder;

    }

}
