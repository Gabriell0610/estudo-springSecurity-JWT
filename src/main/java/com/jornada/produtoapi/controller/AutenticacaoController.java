package com.jornada.produtoapi.controller;

import com.jornada.produtoapi.Service.UsuarioService;
import com.jornada.produtoapi.dto.UsuarioDTO;
import com.jornada.produtoapi.entity.Usuario;
import com.jornada.produtoapi.exceptions.BusinessException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/autenticacao")
@RequiredArgsConstructor
public class AutenticacaoController {

    private final UsuarioService usuarioService;

    // login e retornar um token

    @PostMapping("/login")
    public String fazerLogin(@RequestBody UsuarioDTO dto) throws BusinessException {
        return usuarioService.fazerLogin(dto);
    }

    @PostMapping("/registrar")
    public ResponseEntity<String> registrarUsuario(@RequestBody UsuarioDTO dto) throws BusinessException {
        Usuario novoUsuario = usuarioService.registrarUsuario(dto);
        return ResponseEntity.ok("Usuário cadastrado com sucesso: " + novoUsuario.getLogin());
    }

    @GetMapping("/usuario-logado")
    //NUNCA RETORNE A ENTIDADE NO CONTROLLER E SIM O DTO - USANDO APENAS PARA FINS DIDÁTICOS
    public Usuario recuperandoUsuarioLogado() throws BusinessException {
        return usuarioService.recuprarUsuarioLogado();
    }

}
