package com.jornada.produtoapi.security;

import com.jornada.produtoapi.Service.UsuarioService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final UsuarioService usuarioService;

    @Override
    //Intercepta todas as requisições, valida o token JWT no cabeçalho, autentica o usuário no contexto de segurança do Spring e continua a cadeia de filtros.
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Recupera o token do cabeçalho "Authorization" da requisição
        String tokenBearer = request.getHeader("Authorization");

        // Valida o token e cria um token de autenticação do Spring
        UsernamePasswordAuthenticationToken tokenSpring = usuarioService.validarToken(tokenBearer);

        // Define o usuário como autenticado no contexto de segurança do Spring
        SecurityContextHolder.getContext().setAuthentication(tokenSpring); //Estou logado

        //Executa o próximo filtro
        filterChain.doFilter(request, response);
    }
}
