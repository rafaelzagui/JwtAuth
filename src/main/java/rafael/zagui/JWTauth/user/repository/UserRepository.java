package rafael.zagui.JWTauth.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import rafael.zagui.JWTauth.user.model.User;

import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    User findByEmail(String email);
}
