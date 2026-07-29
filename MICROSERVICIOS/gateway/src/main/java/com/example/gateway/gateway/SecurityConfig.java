package com.example.gateway.gateway;

import java.util.List;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class SecurityConfig {

    private static final String[] SERVICIO = {
        "ADMIN",
        "SERVICIO"
    };

    private static final String[] VENTAS = {
        "ADMIN",
        "VENTAS"
    };

    private static final String[] MARKETING = {
        "ADMIN",
        "MARKETING"
    };

    @Bean
    public FilterRegistrationBean<CorsFilter> customCorsFilter() {

        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(
            List.of("http://localhost:5173")
        );

        config.setAllowedMethods(
            List.of(
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "OPTIONS"
            )
        );

        config.setAllowedHeaders(
            List.of("*")
        );

        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source =
            new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration(
            "/**",
            config
        );

        FilterRegistrationBean<CorsFilter> bean =
            new FilterRegistrationBean<>(
                new CorsFilter(source)
            );

        bean.setOrder(
            Ordered.HIGHEST_PRECEDENCE
        );

        return bean;
    }

    @Bean
    public SecurityFilterChain filterChain(
        HttpSecurity http
    ) throws Exception {

        http
            .cors(AbstractHttpConfigurer::disable)

            .csrf(AbstractHttpConfigurer::disable)

            .authorizeHttpRequests(auth -> auth

                .requestMatchers(
                    HttpMethod.OPTIONS,
                    "/**"
                ).permitAll()

                .requestMatchers(
                    "/oauth2/**",
                    "/login",
                    "/.well-known/**"
                ).permitAll()

                .requestMatchers(
                    HttpMethod.GET,
                    "/api/marcas/**",
                    "/api/categorias/**",
                    "/api/vehiculos/**"
                ).permitAll()

                .requestMatchers(
                    "/register"
                ).hasAnyRole(
                    "ADMIN",
                    "SERVICIO",
                    "VENTAS",
                    "MARKETING"
                )

                .requestMatchers(
                    HttpMethod.GET,
                    "/api/public/servicios/**"
                ).permitAll()

                .requestMatchers(
                    HttpMethod.POST,
                    "/api/public/citas-servicios"
                ).permitAll()

                .requestMatchers(
                    "/api/public/servicios/**",
                    "/api/public/citas-servicios/**"
                ).hasAnyRole(
                    SERVICIO
                )

                .requestMatchers(
                    HttpMethod.POST,
                    "/api/cotizaciones",
                    "/api/public/cotizaciones-vehiculos"
                ).permitAll()

                .requestMatchers(
                    "/api/cotizaciones/**",
                    "/api/public/cotizaciones-vehiculos/**"
                ).hasAnyRole(
                    VENTAS
                )

                .requestMatchers(
                    HttpMethod.POST,
                    "/api/vehiculos/**"
                ).hasAnyRole(
                    VENTAS
                )

                .requestMatchers(
                    HttpMethod.PUT,
                    "/api/vehiculos/**"
                ).hasAnyRole(
                    VENTAS
                )

                .requestMatchers(
                    HttpMethod.DELETE,
                    "/api/vehiculos/**"
                ).hasAnyRole(
                    VENTAS
                )

                .requestMatchers(
                    HttpMethod.GET,
                    "/api/noticias/**",
                    "/api/promociones/**",
                    "/api/imagenes/**"
                ).permitAll()

                .requestMatchers(
                    HttpMethod.POST,
                    "/api/noticias/**",
                    "/api/promociones/**",
                    "/api/imagenes/**"
                ).hasAnyRole(
                    MARKETING
                )

                .requestMatchers(
                    HttpMethod.PUT,
                    "/api/noticias/**",
                    "/api/promociones/**",
                    "/api/imagenes/**"
                ).hasAnyRole(
                    MARKETING
                )

                .requestMatchers(
                    HttpMethod.DELETE,
                    "/api/noticias/**",
                    "/api/promociones/**",
                    "/api/imagenes/**"
                ).hasAnyRole(
                    MARKETING
                )

                .requestMatchers(
                    HttpMethod.GET,
                    "/api/comercial/contacto"
                ).permitAll()

                .requestMatchers(
                    HttpMethod.PUT,
                    "/api/comercial/contacto"
                ).hasAnyRole(
                    MARKETING
                )

                .requestMatchers(
                    "/api/admin/**"
                ).hasRole(
                    "ADMIN"
                )

                .anyRequest()
                .authenticated()
            )

            .oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwt ->
                    jwt.jwtAuthenticationConverter(
                        jwtAuthenticationConverter()
                    )
                )
            );

        return http.build();
    }

    private JwtAuthenticationConverter
    jwtAuthenticationConverter() {

        JwtGrantedAuthoritiesConverter converter =
            new JwtGrantedAuthoritiesConverter();

        converter.setAuthoritiesClaimName(
            "roles"
        );

        converter.setAuthorityPrefix(
            ""
        );

        JwtAuthenticationConverter jwt =
            new JwtAuthenticationConverter();

        jwt.setJwtGrantedAuthoritiesConverter(
            converter
        );

        return jwt;
    }
}