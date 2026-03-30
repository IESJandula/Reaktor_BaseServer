package es.iesjandula.reaktor.base_server.security;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import es.iesjandula.reaktor.base.security.models.DtoAuditoria;
import es.iesjandula.reaktor.base.security.models.DtoAplicacion;
import es.iesjandula.reaktor.base.security.models.DtoUsuarioExtended;
import es.iesjandula.reaktor.base.security.service.PublicKeyGetter;
import es.iesjandula.reaktor.base.utils.BaseConstants;
import es.iesjandula.reaktor.base.utils.BaseException;
import es.iesjandula.reaktor.base_server.utils.BaseServerConstants;
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

    @Autowired
    private AuditoriaRabbitMQ auditoriaRabbitMQ;

    @Value("${" + BaseServerConstants.STRING_SPRING_APPLICATION_NAME + "}")
    private String serviceName;

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
    @SuppressWarnings("null")
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
            // Creamos el objeto de auditoría
            DtoAuditoria dtoAuditoria = new DtoAuditoria();

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

                    // Agregamos la información del usuario al objeto de auditoría
                    dtoAuditoria = this.crearAuditoriaUsuario(usuario);
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

                    // Creamos el objeto de auditoría para la aplicación
                    dtoAuditoria = this.crearAuditoriaAplicacion(aplicacion);
	            }
	        	
	            // Lo establecemos en el contexto de seguridad de Spring
	            SecurityContextHolder.getContext().setAuthentication(authentication) ;
	        }
	
            // Medimos el tiempo de ejecución del filtro
            long startNanos = System.nanoTime();
            try
            {
                // Continuamos con el resto de la cadena de filtros
                chain.doFilter(request, response) ;
            }
            finally
            {
                // Convertimos el tiempo de ejecución a milisegundos
                long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);

                // Agregamos la información común del evento de auditoría
                this.agregarInformacionComunAuditoria(request, durationMs, response.getStatus(), dtoAuditoria);

                // Publicamos el evento de auditoría
                this.auditoriaRabbitMQ.publicarEvento(dtoAuditoria);
            }
        }
    }

    /**
     * Extrae y valida el JWT, devolviendo la info de usuario.
     *
     * @param jwt con el JWT
     * @param claims con la información del usuario del JWT
     * @return DtoUsuario con datos del usuario
     */
    private DtoUsuarioExtended obtenerUsuario(String jwt, Claims claims)
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
    private DtoAplicacion obtenerAplicacion(Claims claims)
    {
        // Extraemos datos de aplicación
        String nombre    = (String) claims.get(BaseConstants.JWT_ATTR_APLICACIONES_ATTRIBUTE_NOMBRE) ;

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get(BaseConstants.JWT_ATTR_APLICACIONES_ATTRIBUTE_ROLES) ;

        // Devolvemos la aplicación con roles
        return new DtoAplicacion(nombre, roles) ;
    }

    /**
     * Agrega la información del usuario al objeto de auditoría.
     *
     * @param usuario con el usuario
     */
    private DtoAuditoria crearAuditoriaUsuario(DtoUsuarioExtended usuario)
    {
        // Creamos el objeto de auditoría
        DtoAuditoria dtoAuditoria = new DtoAuditoria();

        // Seteamos el tipo de evento (USUARIO)
        dtoAuditoria.setTipoEventoUsuarioAplicacion(BaseConstants.STRING_TIPO_EVENTO_USUARIO);

        // Seteamos el email del usuario
        dtoAuditoria.setEmailUsuario(usuario.getEmail());

        // Seteamos el nombre del usuario
        dtoAuditoria.setNombreUsuario(usuario.getNombre());

        // Seteamos los apellidos del usuario
        dtoAuditoria.setApellidosUsuario(usuario.getApellidos());

        // Seteamos la lista de roles
        dtoAuditoria.setRoles(usuario.getRoles());

        // Devolvemos el objeto de auditoría
        return dtoAuditoria;
    }

    /**
     * Crea el objeto de auditoría para la aplicación.
     *
     * @param aplicacion con la aplicación
     */
    private DtoAuditoria crearAuditoriaAplicacion(DtoAplicacion aplicacion)
    {
        // Creamos el objeto de auditoría
        DtoAuditoria dtoAuditoria = new DtoAuditoria();

        // Seteamos el tipo de evento (APLICACION)
        dtoAuditoria.setTipoEventoUsuarioAplicacion(BaseConstants.STRING_TIPO_EVENTO_APLICACION);

        // Seteamos el nombre de la aplicación
        dtoAuditoria.setNombreAplicacion(aplicacion.getNombre());

        // Seteamos la lista de roles
        dtoAuditoria.setRoles(aplicacion.getRoles());

        // Devolvemos el objeto de auditoría
        return dtoAuditoria;
    }

    /**
     * Construye el evento de auditoría para el HTTP request.
     *
     * @param request con la petición HTTP
     * @param durationMs con el tiempo de ejecución en milisegundos
     * @param httpStatus con el estado HTTP
     * @param dtoAuditoria con el objeto de auditoría
     */
	private void agregarInformacionComunAuditoria(HttpServletRequest request, long durationMs, int httpStatus, DtoAuditoria dtoAuditoria)
	{
        // Seteamos el nombre del servicio
		dtoAuditoria.setServiceName(this.serviceName);
		
        // Seteamos el método HTTP
		dtoAuditoria.setMetodo(request.getMethod());

        // Seteamos el endpoint
		dtoAuditoria.setEndpoint(request.getRequestURI());

        // Seteamos el user agent
		dtoAuditoria.setUserAgent(request.getHeader(HttpHeaders.USER_AGENT));
        
        // Seteamos el timestamp
        dtoAuditoria.setTimestamp(LocalDateTime.now());

        // Seteamos el estado HTTP
		dtoAuditoria.setStatus(httpStatus);

        // Seteamos la duración del evento en milisegundos
		dtoAuditoria.setDurationMs(durationMs);
	}
}
