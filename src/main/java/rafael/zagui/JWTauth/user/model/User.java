package rafael.zagui.JWTauth.user.model;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.UUID;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
@Table(schema = "public", name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue
    private UUID id;

    private String name;

    @Column(unique = true) // Garante que o email seja único no banco de dados
    private String email;

    private String password;

    @Column(name = "roles", columnDefinition = "text")
    @Enumerated(EnumType.STRING)
    private UserRole role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Converte a role do usuário para uma lista de authorities
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getUsername() {
        return email; // Usa o email como username
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // Conta não expirada
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Conta não bloqueada
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Credenciais não expiradas
    }

    @Override
    public boolean isEnabled() {
        return true; // Usuário habilitado
    }
}
