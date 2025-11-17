package es.iesjandula.reaktor.base_server.security;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import es.iesjandula.reaktor.base.security.models.DtoAplicacion;
import es.iesjandula.reaktor.base.security.models.DtoUsuarioExtended;
import es.iesjandula.reaktor.base.security.service.PublicKeyGetter;
import es.iesjandula.reaktor.base.utils.BaseConstants;
import es.iesjandula.reaktor.base.utils.BaseException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filtro para validar el JWT en cada petición (una sola vez por request).
 */
@Component
public class JwtRequestFilter extends OncePerRequestFilter
{
    /** Atributo - JWT Parser */
    private JwtParser jwtParser;

    @Autowired
    private PublicKeyGetter publicKeyGetter;

    /**
     * En lugar de usar @PostConstruct, usamos initFilterBean() 
     * para inicializar el parser una vez que el filtro sea creado por Spring.
     */
    @Override
    protected void initFilterBean() throws ServletException
    {
        super.initFilterBean();
        try
        {
            this.jwtParser = Jwts.parser()
                                 .verifyWith(this.publicKeyGetter.obtenerClavePublica()) 
                                 .build();
        }
        catch (BaseException e)
        {
            // Si ocurre un error al obtener la clave pública, lo encapsulamos como ServletException
            throw new ServletException("Error al obtener la clave pública para JWT Parser", e);
        }
    }

    /**
     * @param request   con la petición de entrada
     * @param response  con la respuesta
     * @param chain     cadena de filtros
     * 
     * Filtra las solicitudes para verificar el JWT, excepto para ciertas rutas.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException
    {
        String requestURI = request.getRequestURI(); 
        
        // Rutas exentas de filtrado
        if (requestURI.equals("/firebase/token/user") || requestURI.equals("/firebase/token/app") || requestURI.startsWith("/proyectolince"))
        {
            chain.doFilter(request, response) ;
        }
        else
        {
	        // Obtenemos el valor de la cabecera "Authorization"
	        final String authorizationHeader = request.getHeader("Authorization") ;
	        
	        // Comprobamos que venga relleno y con el prefijo Bearer
	        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer "))
	        {
	            // Eliminamos el prefijo "Bearer " del encabezado 
	            String jwt = authorizationHeader.substring(7);
	            
	            // Parseamos y verificamos el token, obteniendo los claims
	            Claims claims = this.jwtParser.parseSignedClaims(jwt).getPayload();
	            
	            // Creamos el objeto de autenticación
	            UsernamePasswordAuthenticationToken authentication = null ;
	            
	            // Verificamos si es una aplicación o un usuario
	            if (claims.containsKey(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_EMAIL))
	            {
	            	// Extraer info de usuario del JWT
	            	DtoUsuarioExtended usuario = this.obtenerUsuario(jwt, claims) ;
	            	
	            	// Creamos la lista de roles como GrantedAuthority para Spring Security
	            	List<GrantedAuthority> authorities = usuario.getRoles()
										            			.stream()
										            			.map(SimpleGrantedAuthority::new)
										            			.collect(Collectors.toList()) ;
	            	
	            	// Creamos el objeto de autenticación
	            	authentication = new UsernamePasswordAuthenticationToken(usuario, null, authorities) ;
	            }
	            else
	            {
	            	// Extraer info de aplicación del JWT
	            	DtoAplicacion aplicacion = this.obtenerAplicacion(claims) ;
	            	
	            	// Creamos la lista de roles como GrantedAuthority para Spring Security
	            	List<GrantedAuthority> authorities = aplicacion.getRoles()
											            		   .stream()
											            		   .map(SimpleGrantedAuthority::new)
											            		   .collect(Collectors.toList()) ;
	            	
	            	// Creamos el objeto de autenticación
	            	authentication = new UsernamePasswordAuthenticationToken(aplicacion, null, authorities) ;	            	
	            }
	        	
	            // Lo establecemos en el contexto de seguridad de Spring
	            SecurityContextHolder.getContext().setAuthentication(authentication) ;
	        }
	
	        // Continuamos con el resto de la cadena de filtros
	        chain.doFilter(request, response) ;
        }
    }

    /**
     * Extrae y valida el JWT, devolviendo la info de usuario.
     *
     * @param jwt con el JWT
     * @param claims con la información del usuario del JWT
     * @return DtoUsuario con datos del usuario
     */
    public DtoUsuarioExtended obtenerUsuario(String jwt, Claims claims)
    {
        // Extraemos datos de usuario
        String email           = (String) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_EMAIL);
        String nombre          = (String) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_NOMBRE);
        String apellidos       = (String) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_APELLIDOS);
        String departamento    = (String) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_DEPARTAMENTO);
        String fechaNacimiento = (String) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_FECHA_NACIMIENTO);

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_ROLES);

        // Devolvemos el usuario con roles
        DtoUsuarioExtended dtoUsuarioExtended = new DtoUsuarioExtended() ;
        
        dtoUsuarioExtended.setEmail(email);
        dtoUsuarioExtended.setNombre(nombre);
        dtoUsuarioExtended.setApellidos(apellidos);
        dtoUsuarioExtended.setDepartamento(departamento);
        dtoUsuarioExtended.setFechaNacimiento(fechaNacimiento);
        dtoUsuarioExtended.setRoles(roles);
        dtoUsuarioExtended.setJwt(jwt);
        
        return dtoUsuarioExtended;
    }
    
    /**
     * Extrae y valida el JWT, devolviendo la info de usuario.
     * 
     * @param claims con la información del usuario del JWT
     * @return DtoUsuario con datos del usuario
     */
    public DtoAplicacion obtenerAplicacion(Claims claims)
    {
        // Extraemos datos de aplicación
        String nombre    = (String) claims.get(BaseConstants.JWT_ATTR_APLICACIONES_ATTRIBUTE_NOMBRE) ;

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get(BaseConstants.JWT_ATTR_APLICACIONES_ATTRIBUTE_ROLES) ;

        // Devolvemos la aplicación con roles
        return new DtoAplicacion(nombre, roles) ;
    }
}
