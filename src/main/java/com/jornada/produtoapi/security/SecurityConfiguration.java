package com.jornada.produtoapi.security;

import com.jornada.produtoapi.Service.UsuarioService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity //Habilita o Spring Security para a aplicação, ativando os recursos de segurança.
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final UsuarioService usuarioService;

    @Bean
    // Esse método configura a cadeia de filtros de segurança, que define como as requisições serão protegidas.
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //permissões e filtros
        http.csrf(AbstractHttpConfigurer::disable); //Desabilita a proteção CSRF (Cross-Site Request Forgery). Isso é comum quando não há frontend separado, ou seja, quando não se tem formulários vulneráveis a esse tipo de ataque.
        http.cors(Customizer.withDefaults()); // Habilitando o CORS
        //Define as regras de autorização para as requisições
        http.authorizeHttpRequests((authz) ->
                authz.requestMatchers("/autenticacao/**").permitAll() //permite acesso total a rota "autenticacao"
                        .requestMatchers(HttpMethod.POST, "/cliente/**").hasRole("ADMIN") // O método POST na rota "cliente" só pode ser feita port quem tem o cardo de (ADMIN)
                        .requestMatchers("/cliente/**").hasRole("VENDAS") //ROLE_ADMIN
                        .requestMatchers("/fornecedor/**").hasRole("FINANCEIRO") //ROLE_FINANCEIRO
                        .requestMatchers("/produto/**").hasAnyRole("VENDAS","FINANCEIRO") //ROLE_VENDAS | A rota 'produto', pode ser acessada por quem ter o cardo de (VENDA E FINANCEIRO)
                        .anyRequest().authenticated() // só acessa se tiver autenticado
                //Regas mais específicas acima
                //Regras mais genéricos abaixo
        );

        //Aqui é como se dissesse da seguinte forma - antes de quaqluer requisição, faça o tokenAuthenticationFilter
        http.addFilterBefore(new TokenAuthenticationFilter(usuarioService), UsernamePasswordAuthenticationFilter.class);

        return http.build(); //Finaliza e retorna o objeto HttpSecurity com as configurações de segurança definidas.
    };


    @Bean
    //Configura quais caminhos devem ser ignorados pelo filtro de segurança
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/v3/api-docs",
                "/v3/api-docs/**",
                "/swagger-resources/**",
                "/swagger-ui/**"
        );
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

}
