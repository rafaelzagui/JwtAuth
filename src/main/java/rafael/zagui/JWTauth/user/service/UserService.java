package rafael.zagui.JWTauth.user.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rafael.zagui.JWTauth.user.model.User;
import rafael.zagui.JWTauth.user.model.UserRole;
import rafael.zagui.JWTauth.user.repository.UserRepository;
@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User createUser(User createUserRequest) {
        // Verifica se o email já está em uso
        if (userRepository.findByEmail(createUserRequest.getEmail()) != null) {
            throw new RuntimeException("Email já está em uso");
        }

        // Cria um novo usuário
        User user = new User();
        user.setName(createUserRequest.getName());
        user.setEmail(createUserRequest.getEmail());
        user.setPassword(passwordEncoder.encode(createUserRequest.getPassword())); // Codifica a senha
        user.setRole(createUserRequest.getRole());

        // Salva o usuário no banco de dados
        return userRepository.save(user);
    }
}
