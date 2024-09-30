package com.jornada.produtoapi.Service;

import com.jornada.produtoapi.dto.UsuarioDTO;
import com.jornada.produtoapi.entity.Cargo;
import com.jornada.produtoapi.entity.Usuario;
import com.jornada.produtoapi.exceptions.BusinessException;
import com.jornada.produtoapi.repositories.UsuarioRepository;
import com.jornada.produtoapi.security.SecurityConfiguration;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    public UsuarioService(@Lazy UsuarioRepository usuarioRepository, // O Lazy faz com que não ocorra a referência cíclica
                          @Lazy AuthenticationManager authenticationManager,
                          @Lazy PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }

    @Value("${jwt.validade.token}")
    private String validadeJWT;

    @Value("${jwt.secret}")
    private String secret;

    public String fazerLogin(UsuarioDTO dto) throws BusinessException {
        UsernamePasswordAuthenticationToken dtoDoSpring = new UsernamePasswordAuthenticationToken(
                dto.login(),
                dto.senha()
        );

        try {
            // Autentica as credenciais do usuário usando o AuthenticationManager do Spring
            Authentication autenticacao = authenticationManager.authenticate(dtoDoSpring); //Pegando o Objeto Usuario
            System.out.println("Autenticação bem-sucedida: {}" + autenticacao);

            // Pega o objeto do usuário autenticado (que foi carregado pelo Spring Security) e transforma ele é um objeto de Usuario
            Usuario usuario = (Usuario) autenticacao.getPrincipal();

            // Extrai os cargos do usuário e transforma em uma lista de strings
            var cargos = usuario.getCargos().stream()
                    .map(data -> data.getNome())
                    .toList();

            // Define a data atual e a data de expiração do token (validade do JWT)
            Date dataAtual = new Date();
            Date dataExpiracao = new Date(dataAtual.getTime() + Long.parseLong(validadeJWT));

            // Gera o token JWT com os dados do usuário e os cargos
            String jwtGerado = Jwts.builder()
                    .setIssuer("produto-api") // Define o emissor do JWT (identificação da aplicação)
                    .claim("CARGOS", cargos) // Adicionando os cargos ao JWT
                    .setSubject(usuario.getIdUsuario().toString()) //Id do usuário vai ficar no subject
                    .setIssuedAt(dataAtual) // data que o jwt foi gerado
                    .setExpiration(dataExpiracao) // data de expiração
                    .signWith(SignatureAlgorithm.HS256, secret.getBytes()) // Assina o token com um algoritmo de criptografia
                    .compact(); //Gerando jwt
            return jwtGerado;
        }catch (AuthenticationException ex) {
            throw new BusinessException("Usuário e senha inválidos");
        }
    }

    public UsernamePasswordAuthenticationToken validarToken(String token) {
        if(token == null) {
            return null;
        }

        String tokenLimpo = token.replace("Bearer ", ""); // Remove o prefixo "Bearer " do token

        Claims claims = Jwts.parser()
                .setSigningKey(secret.getBytes()) // Verifica o token usando a chave secreta
                .parseClaimsJws(tokenLimpo) // decodificando e validando o token
                .getBody(); // pegando o payload
        String idUsuario = claims.getSubject(); // id do usuário que está vindo do subject do payload

        List<String> cargos = claims.get("CARGOS", List.class); //Colocando em um array todos os cargos do usuário

        //Transformando cada cargo do usuário em uma instância de SimpleGrantedAuthority
        var parseCargos = cargos.stream()
                .map(cargoStr -> new SimpleGrantedAuthority(cargoStr))
                .toList();

        // Cria um objeto de autenticação do Spring com o ID do usuário
        UsernamePasswordAuthenticationToken tokenSpring
                = new UsernamePasswordAuthenticationToken(idUsuario, null, parseCargos);
        return tokenSpring; // Retorna o token de autenticação

    }

    public Optional<Usuario> findByLogin(String login) {
        return usuarioRepository.findByLogin(login);
    }

    public Usuario registrarUsuario(UsuarioDTO dto) throws BusinessException {
        // Verifica se o usuário já existe
        if(usuarioRepository.findByLogin(dto.login()).isPresent()) {
            throw new BusinessException("Usuário já cadastrado.");
        }

        // Cria um novo objeto de usuário e criptografa a senha
        var senhaCriptografada = passwordEncoder.encode(dto.senha()); // Criptografando a senha
        Usuario novoUsuario = new Usuario(dto.login(),senhaCriptografada);
        // Salva o usuário no banco de dados
        return usuarioRepository.save(novoUsuario);
    }

    public Integer recuperarIdUsuarioLogado() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); //Pegando o id do usuario
        Object idUsuario = authentication.getPrincipal();
        return Integer.parseInt(idUsuario.toString());

    }

    public Usuario recuprarUsuarioLogado() throws BusinessException {
        var idUsuario = recuperarIdUsuarioLogado();
        return usuarioRepository.findById(idUsuario).orElseThrow(() ->new BusinessException("Usuario não existe"));
    }
}
