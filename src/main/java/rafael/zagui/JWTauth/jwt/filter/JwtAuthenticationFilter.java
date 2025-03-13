package rafael.zagui.JWTauth.jwt.filter;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import rafael.zagui.JWTauth.jwt.util.JwtUtil;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = extractToken(request);
        if (token != null) {
            try {
                DecodedJWT decodedJWT = jwtUtil.validateToken(token); // Valida o token
                String email = decodedJWT.getSubject(); // Extrai o email do token

                if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    // Cria um objeto Jwt compatível com o Spring Security
                    Jwt jwt = Jwt.withTokenValue(token)
                            .header("alg", "HS256") // Algoritmo de assinatura
                            .claim("sub", email) // Subject (email)
                            .claim("roles", Collections.singletonList("USER")) // Roles do usuário
                            .issuedAt(Instant.now()) // Data de emissão
                            .expiresAt(decodedJWT.getExpiresAt().toInstant()) // Data de expiração
                            .build();

                    // Cria uma autenticação JWT
                    var authentication = new JwtAuthenticationToken(jwt, Collections.emptyList());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception e) {
                // Token inválido
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token inválido");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }


    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7); // Remove o prefixo "Bearer "
        }
        return null;
    }
}