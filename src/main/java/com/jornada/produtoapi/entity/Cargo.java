package com.jornada.produtoapi.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;

@Entity
@Table(name= "cargo")
@Getter
@Setter
public class Cargo implements GrantedAuthority {

    @Id @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "CARGO_SEQUENCIA")
    @SequenceGenerator(name="CARGO_SEQUENCIA", sequenceName = "seq_cargo", allocationSize = 1)
    @Column(name = "id_cargo")
    private Integer idCargo;
    private String nome;

    @JsonIgnore
    @ManyToMany
    @JoinTable(name = "USUARIO_CARGO",
        joinColumns = @JoinColumn(name = "id_cargo"),
        inverseJoinColumns = @JoinColumn(name= "id_usuario"))
    public Set<Usuario> usuarios;

    @Override
    public String getAuthority() {
        return nome;
    }
}
