package com.jornada.produtoapi.security;

import com.jornada.produtoapi.Service.UsuarioService;
import com.jornada.produtoapi.entity.Usuario;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService implements UserDetailsService {

    private final UsuarioService usuarioService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
       Optional<Usuario> usuario = usuarioService.findByLogin(username);

       if(usuario.isPresent()) {
           return usuario.get();
       }

        throw new UsernameNotFoundException("Usuario não encontrado");
    }
}
