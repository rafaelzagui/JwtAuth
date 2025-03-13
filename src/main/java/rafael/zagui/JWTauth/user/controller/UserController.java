package rafael.zagui.JWTauth.user.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import rafael.zagui.JWTauth.jwt.util.JwtUtil;
import rafael.zagui.JWTauth.user.dto.LoginRequest;
import rafael.zagui.JWTauth.user.model.User;
import rafael.zagui.JWTauth.user.service.UserService;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserService userService;


    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
        try {
            // Autentica o usuário usando o email e a senha
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );

            // Gera o token JWT
            String token = jwtUtil.generateToken(loginRequest.getEmail());
            return ResponseEntity.ok(token);
        } catch (UsernameNotFoundException e) {
            // Caso o usuário não seja encontrado
            return ResponseEntity.status(401).body("Credenciais inválidas");
        } catch (Exception e) {
            // Outros erros de autenticação
            return ResponseEntity.status(500).body("Erro durante a autenticação");
        }
    }
    @PostMapping("/register")
    public ResponseEntity<String> createUser(@RequestBody User createUserRequest) {
        try {
            // Cria o usuário
            userService.createUser(createUserRequest);
            return ResponseEntity.ok("Usuário criado com sucesso");
        } catch (RuntimeException e) {
            // Caso o email já esteja em uso
            return ResponseEntity.status(400).body(e.getMessage());
        } catch (Exception e) {
            // Outros erros
            return ResponseEntity.status(500).body("Erro ao criar usuário");
        }
    }
}