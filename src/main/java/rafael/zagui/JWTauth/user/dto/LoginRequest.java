package rafael.zagui.JWTauth.user.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequest {
    // Getters e Setters
    private String email;
    private String password;

}
