package com.workshop.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class FilterUtils {
    public static String getTokenFromAuthorizationHeader(String authorizationHeader) {
        return authorizationHeader.substring("Bearer ".length());
    }

    public static Algorithm getAlgorithm() {
        return Algorithm.HMAC256("secret".getBytes());
    }
    public static DecodedJWT getDecodedJWT(String token) {
        Algorithm algorithm = getAlgorithm();
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        return jwtVerifier.verify(token);
    }

    public static String getUsernameFromDecodedJWT(DecodedJWT decodedJWT) {
        return decodedJWT.getSubject();
    }

    public static String[] getRolesFromDecodedJWT(DecodedJWT decodedJWT) {
        return decodedJWT.getClaim("roles").asArray(String.class);
    }
}
