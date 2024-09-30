package com.jornada.produtoapi.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.jornada.produtoapi.dto.UsuarioDTO;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

@Entity
@Table(name="usuario")
@Getter
@Setter
public class Usuario implements UserDetails {

    @Id @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "USUARIO_SEQUENCIA")
    @SequenceGenerator(name="USUARIO_SEQUENCIA", sequenceName = "seq_usuario", allocationSize = 1)
    @Column(name = "id_usuario")
    private Integer idUsuario;

    private String login;
    private String senha;

    @ManyToMany
    @JoinTable(name = "USUARIO_CARGO",
            joinColumns = @JoinColumn(name = "id_usuario"),
            inverseJoinColumns = @JoinColumn(name= "id_cargo"))
    public Set<Cargo> cargos;

    public Usuario(){}

    public Usuario(String login, String senha) {
        this.login = login;
        this.senha = senha;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return cargos;
    }

    @Override
    public String getPassword() {
        return senha;
    }

    @Override
    public String getUsername() {
        return login;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // A conta não está expirada
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // não está bloqueado
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Muda para true porque as credencias não estão expiradas
    }

    @Override
    public boolean isEnabled() {
        return true; // muda para true porque sempre vai estar ativo
    }
}
