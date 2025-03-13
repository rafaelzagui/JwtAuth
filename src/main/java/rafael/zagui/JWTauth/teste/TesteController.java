package rafael.zagui.JWTauth.teste;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TesteController {
    @GetMapping("/")
    public String getProtectedData(@AuthenticationPrincipal Jwt jwt) {
        String email = jwt.getClaimAsString("sub"); // Extrai o email do token
        return "Dados protegidos para o usuário: " + email;
    }
}
