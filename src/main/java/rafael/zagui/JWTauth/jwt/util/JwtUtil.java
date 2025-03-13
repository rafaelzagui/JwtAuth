package rafael.zagui.JWTauth.jwt.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}") // Chave secreta para assinar o token
    private String secret;

    @Value("${jwt.expiration}") // Tempo de expiração do token
    private long expiration;

    // Gera um token JWT
    public String generateToken(String email) {
        return JWT.create()
                .withSubject(email) // Define o assunto (email do usuário)
                .withExpiresAt(new Date(System.currentTimeMillis() + expiration)) // Define a expiração
                .sign(Algorithm.HMAC256(secret)); // Assina o token com a chave secreta
    }

    // Valida o token JWT e retorna as informações (claims)
    public DecodedJWT validateToken(String token) throws JWTVerificationException {
        return JWT.require(Algorithm.HMAC256(secret))
                .build()
                .verify(token); // Valida o token
    }
}
