package br.com.examplejwt.security.config.jwt;

import br.com.examplejwt.security.service.impl.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;

import static io.jsonwebtoken.SignatureAlgorithm.HS512;
import static java.util.Objects.isNull;
import static org.springframework.http.ResponseCookie.from;

/**
 * Utilitário responsável por criar, obter, validar, converter informações do Token em conteúdo, ou conteúdo num token.
 * <br />
 * Utility responsible for creating, obtaining, validating, converting Token information into content, or content into a token
 *
 * @author Marcio
 */
@Component
public class JwtUtils {

    private static final String API = "/api";
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtils.class);

    @SuppressWarnings("UnusedDeclaration")
    @Value("${example.jwt.secret}")
    private String jwtSecret;

    @SuppressWarnings("UnusedDeclaration")
    @Value("${example.jwt.expirationMs}")
    private int jwtExpirationMs;

    @SuppressWarnings("UnusedDeclaration")
    @Value("${example.jwt.cookieName}")
    private String jwtCookie;

    public String getJwtFromCookies(final HttpServletRequest request) {
        final Cookie cookie = WebUtils.getCookie(request, jwtCookie);
        return isNull(cookie) ? null : cookie.getValue();
    }

    public ResponseCookie generateJwtCookie(final UserDetailsImpl userPrincipal) {
        final String jwt = generateJwtTokenFromUserName(userPrincipal.getUsername());
        return from(jwtCookie, jwt).path(API).maxAge((long) 24 * 60 * 60).httpOnly(true).build();
    }

    public ResponseCookie getCleanJwtCookie() {
        return from(jwtCookie, "").path(API).build();
    }

    public String generateJwtTokenFromUserName(final String userName) {
        return Jwts.builder()
                .setSubject(userName)
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(final String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(final String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            LOGGER.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            LOGGER.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            LOGGER.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            LOGGER.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            LOGGER.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
