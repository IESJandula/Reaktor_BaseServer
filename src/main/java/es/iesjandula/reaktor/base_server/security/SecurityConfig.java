package es.iesjandula.reaktor.base_server.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author Francisco Manuel Benítez Chico
 *  
 * Habilitamos la configuración de seguridad personalizada (@EnableWebSecurity) en vez de la predeterminada de Spring Security
 * Desactivamos la autoconfiguración del UserDetailsService ya que usamos JWT
 */
@Configuration
@EnableWebSecurity
@EnableAutoConfiguration(exclude = {UserDetailsServiceAutoConfiguration.class})
public class SecurityConfig
{
	@Autowired
	private JwtRequestFilter jwtRequestFilter ;
	
	/**
	 * Este método genera un bean gestionado por el contenedor de Spring
	 * @param http HTTP Security
	 * @return define cómo se aplicará la seguridad a las solicitudes HTTP
	 * @throws Exception una excepción relacionada con este proceso
	 */
	@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
	{
        http
        
        // Deshabilitar la protección CSRF, ya que se usa JWT
        
        	.csrf(csrf -> csrf.disable())
            
        // Configuramos las reglas de autorización para las solicitudes HTTP

            .authorizeHttpRequests(authz -> authz
            		
            	// Permitimos que todas las solicitudes a las rutas públicas sean accesibles sin autenticación
            		
                .requestMatchers("/public/**", "/notifications/gmail/oauth2callback", "/firebase/token/user", "/firebase/token/app", "/proyectolince/**").permitAll()
                
                // Para cualquier otra ruta que no sean las anteriores, requerimos autenticación
                
                .anyRequest().authenticated() 
            )
            
            // Configuramos la administración de sesiones. La política de sesiones es "sin estado" (STATELESS):
            // no se guardará una sesión en el servidor
            
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            ) ;
        
        // Añadimos el filtro personalizado JwtRequestFilter para que se ejecute antes 
        // de la autenticación estándar de Spring. Este filtro se encargará de validar el token JWT 
        // antes de que Spring Security gestione la autenticación

        http.addFilterBefore(this.jwtRequestFilter, UsernamePasswordAuthenticationFilter.class) ;

        // Devolvemos el objeto HttpSecurity construido, que define cómo se aplicará la seguridad 
        // a las solicitudes HTTP

        return http.build() ;
    }
}



