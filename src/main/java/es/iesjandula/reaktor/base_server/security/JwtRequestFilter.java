package es.iesjandula.reaktor.base_server.security;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filtro para validar el JWT en cada petición (una sola vez por request).
 * <p>
 * Acepta dos tipos de token, distinguidos por el claim {@code iss} (issuer):
 * </p>
 * <ul>
 *   <li><b>JWT propio del ecosistema Reaktor</b> (sin issuer de Google): firmado con la clave privada del ecosistema y
 *       verificado con la clave pública ({@link PublicKeyGetter}). Trae los claims propios (email, roles, etc.).</li>
 *   <li><b>JWT de Google/Firebase</b> (issuer {@code https://securetoken.google.com/<projectId>}): verificado contra las
 *       claves públicas de Google mediante {@link GoogleTokenVerifier}. Como NO trae roles del ecosistema, la
 *       autorización se resuelve por <b>allowlist de emails</b> (variable de entorno) y roles configurables.</li>
 * </ul>
 */
@Component
public class JwtRequestFilter extends OncePerRequestFilter
{
    /** Logger de la clase */
    private static final Logger log = LoggerFactory.getLogger(JwtRequestFilter.class);

    /** Atributo - JWT Parser (para el JWT propio del ecosistema Reaktor) */
    private JwtParser jwtParser;

    @Autowired
    private PublicKeyGetter publicKeyGetter;

    @Autowired
    private GoogleTokenVerifier googleTokenVerifier;

    @Autowired
    private AuditoriaRabbitMQ auditoriaRabbitMQ;

    @Value("${" + BaseServerConstants.STRING_SPRING_APPLICATION_NAME + "}")
    private String serviceName;

    /** Allowlist de emails autorizados para tokens de Google (lista separada por comas) */
    @Value("${reaktor.google.allowedEmails:}")
    private String emailsGooglePermitidosString;

    /** Conjunto de emails permitidos (en minúsculas) parseado de {@link #emailsGooglePermitidosString} */
    private Set<String> emailsGooglePermitidos;

    /** Roles a asignar a los usuarios autenticados vía token de Google (lista separada por comas) */
    @Value("${reaktor.google.defaultRoles:}")
    private String rolesGooglePermitidosString;

    /** Lista de roles permitidos para usuarios de Google parseada de {@link #rolesGooglePermitidosString} */
    private List<String> rolesGooglePermitidos;

    /** ObjectMapper para leer el issuer del payload del JWT sin verificar (solo para enrutado) */
    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostConstruct
    public void inicializar() throws BaseException
    {
        // Parseamos la allowlist de emails (en minúsculas) y los roles por defecto para tokens de Google
        this.parsearEmailsGooglePermitidos();
        this.parsearRolesGooglePermitidos();
    }

    /**
     * Parsea una cadena separada por comas en un conjunto de valores en minúsculas (sin vacíos).
     */
    private void parsearEmailsGooglePermitidos()
    {
        // Creamos un nuevo conjunto de valores en minúsculas
        this.emailsGooglePermitidos = new HashSet<>();

        // Si la cadena no es null y no está vacía, procesamos cada valor
        if (this.emailsGooglePermitidosString != null && !this.emailsGooglePermitidosString.isBlank())
        {
            // Iteramos sobre los valores separados por comas
            for (String valor : this.emailsGooglePermitidosString.split(","))
            {
                // Limpiamos el valor y lo convertimos a minúsculas
                String limpio = valor.trim().toLowerCase();

                // Si el valor no está vacío, lo añadimos al conjunto
                if (!limpio.isEmpty())
                {
                    // Añadimos el valor al conjunto
                    this.emailsGooglePermitidos.add(limpio);
                }
            }
        }
    }

    /**
     * Parsea una cadena separada por comas en una lista de valores (sin vacíos).
     */
    private void parsearRolesGooglePermitidos()
    {
        // Creamos una nueva lista de valores
        this.rolesGooglePermitidos = new ArrayList<>();

        // Si la cadena no es null y no está vacía, procesamos cada valor
        if (this.rolesGooglePermitidosString != null && !this.rolesGooglePermitidosString.isBlank())
        {
            // Iteramos sobre los valores separados por comas
            for (String valor : this.rolesGooglePermitidosString.split(","))
            {
                // Limpiamos el valor y lo convertimos a minúsculas
                String limpio = valor.trim();

                // Si el valor no está vacío, lo añadimos a la lista
                if (!limpio.isEmpty())
                {
                    // Añadimos el valor a la lista
                    this.rolesGooglePermitidos.add(limpio);
                }
            }
        }
    }

    /**
     * En lugar de usar @PostConstruct, usamos initFilterBean() 
     * para inicializar el parser una vez que el filtro sea creado por Spring.
     */
    @Override
    protected void initFilterBean() throws ServletException
    {
        // Inicializamos el filtro
        super.initFilterBean();

        try
        {
            // Parseamos el JWT con la clave pública
            this.jwtParser = Jwts.parser()
                                 .verifyWith(this.publicKeyGetter.obtenerClavePublica()) 
                                 .build();
        }
        catch (BaseException baseException)
        {
            // Si ocurre un error al obtener la clave pública, lo encapsulamos como ServletException
            throw new ServletException("Error al obtener la clave pública para JWT Parser", baseException);
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
            this.doFilterInternalPosibleJwt(request, response, chain);
        }
    }

    /**
     * Filtra las solicitudes para verificar el JWT, excepto para ciertas rutas.
     * 
     * @param request   con la petición de entrada
     * @param response  con la respuesta
     * @param chain     cadena de filtros
     */
    private void doFilterInternalPosibleJwt(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException
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

            // Leemos el issuer (sin verificar firma) SOLO para decidir qué verificador aplicar
            String issuer = this.extraerIssuer(jwt);

            // Creamos el objeto de autenticación
            UsernamePasswordAuthenticationToken authentication = null ;

            // Si el issuer es un token de Google, procesamos el token de Google
            boolean esTokenGoogle = this.esTokenGoogle(issuer);
            if (esTokenGoogle)
            {
                // Verificamos el token contra las claves públicas de Google y aplicamos la allowlist de emails.
                authentication = this.procesarTokenGoogle(dtoAuditoria, jwt);
            }
            else
            {
                authentication = this.procesarTokenPropio(dtoAuditoria, jwt);
            }

            // Si la autenticación es distinta de null ...
            if (authentication != null)
            {
                // ... establecemos la autenticación en el contexto de seguridad de Spring
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
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

    /**
     * Lee el claim {@code iss} (issuer) del payload del JWT SIN verificar la firma. Se usa exclusivamente para enrutar
     * el token al verificador adecuado (propio vs. Google); la verificación real de la firma se hace después.
     *
     * @param jwt token en formato compacto (header.payload.signature)
     * @return el issuer, o null si no se puede leer
     */
    private String extraerIssuer(String jwt)
    {
        // Inicializamos el issuer a null
        String issuer = null;

        try
        {
            // Comprobamos que el JWT no sea null
            String[] partes = jwt.split("\\.");

            // Comprobamos que el JWT tenga al menos 2 partes
            if (partes.length >= 2)
            {
                // Decodificamos el segmento de payload (base64url) y leemos el campo "iss"
                byte[] payloadBytes = Base64.getUrlDecoder().decode(partes[1]);

                // Leemos el payload como un JsonNode
                JsonNode payload = this.objectMapper.readTree(payloadBytes);

                // Leemos el claim "iss" del payload
                JsonNode issuerNode = payload.get("iss");

                // Seteamos el issuer si no es null
                if (issuerNode != null)
                {
                    // Convertimos el issuer a String
                    issuer = issuerNode.asText();
                }
            }
        }
        catch (Exception exception)
        {
            log.error("Error al extraer el issuer del JWT", exception);
        }
        
        // Devolvemos el issuer
        return issuer;
    }

    /**
     * Indica si el issuer corresponde a un token emitido por Google/Firebase.
     *
     * @param issuer issuer leído del token
     * @return true si es un token de Google
     */
    private boolean esTokenGoogle(String issuer)
    {
        // Devolvemos true si el issuer es null o si es un token de Google
        return issuer != null &&
               (issuer.startsWith(BaseServerConstants.GOOGLE_ISSUER_PREFIX) ||
                issuer.equals(BaseServerConstants.GOOGLE_ISSUER_ACCOUNTS_GOOGLE_COM) ||
                issuer.equals(BaseServerConstants.GOOGLE_ISSUER_ACCOUNTS_GOOGLE_COM_WITH_HTTPS));
    }

    /**
     * Verifica un token de Google y, si el email está en la allowlist, construye la autenticación del usuario.
     * <p>
     * Como el token de Google NO trae roles del ecosistema Reaktor, la autorización se resuelve por allowlist de
     * emails (variable de entorno {@code REAKTOR_GOOGLE_ALLOWED_EMAILS}) y los roles se toman de
     * {@code REAKTOR_GOOGLE_DEFAULT_ROLES}. Si el token no es válido o el email no está autorizado, devuelve null
     * (no se establece autenticación, coherente con el tratamiento de un token inválido).
     *
     * @param jwt token de Google
     * @param dtoAuditoria con el objeto de auditoría
     * @return la autenticación construida, o null si no procede autenticar
     * @throws IOException si ocurre un error al procesar el token de Google
     */
    private UsernamePasswordAuthenticationToken procesarTokenGoogle(DtoAuditoria dtoAuditoria, String jwt) throws IOException
    {
        // Inicializamos la autenticación a null
        UsernamePasswordAuthenticationToken authentication = null;

        try
        {
            // Verificamos firma, expiración e issuer contra las claves públicas de Google
            Claims claims = this.googleTokenVerifier.verificarToken(jwt);

            // Extraemos el email (y el nombre si viene)
            String email  = claims.get(BaseServerConstants.JWT_ATTR_GOOGLE_ATTRIBUTE_EMAIL, String.class);
            String nombre = claims.get(BaseServerConstants.JWT_ATTR_GOOGLE_ATTRIBUTE_NAME, String.class);

            // Si el email es nulo o no se encuentra en la allowlist, no se autentica
            if (email == null || !this.emailsGooglePermitidos.contains(email.toLowerCase()))
            {
                // Creamos el mensaje de error
                String errorMessage = BaseServerConstants.ERROR_MESSAGE_EMAIL_GOOGLE_NOT_AUTHORIZED_DESC + email;

                // Logueamos el error y lanzamos una excepción
                log.error(errorMessage);
                throw new BaseException(BaseServerConstants.ERROR_MESSAGE_EMAIL_GOOGLE_NOT_AUTHORIZED_CODE, errorMessage);
            }

            // Construimos el usuario de Google. Roles = los configurados por defecto (mínimo privilegio si está vacío)
            DtoUsuarioExtended usuario = new DtoUsuarioExtended();

            // Seteamos los datos del usuario
            usuario.setEmail(email);
            usuario.setNombre(nombre);
            usuario.setRoles(this.rolesGooglePermitidos);
            usuario.setJwt(jwt);

            // Creamos la lista de roles como GrantedAuthority para Spring Security
            List<GrantedAuthority> authorities = this.rolesGooglePermitidos
                                                     .stream()
                                                     .map(SimpleGrantedAuthority::new)
                                                     .collect(Collectors.toList());

            // Creamos el objeto de autenticación
            authentication = new UsernamePasswordAuthenticationToken(usuario, null, authorities);

            // Rellenamos el objeto de auditoría con la información del usuario
            this.rellenarAuditoriaUsuario(dtoAuditoria, true, usuario);

            // Devolvemos la autenticación
            return authentication;
        }
        catch (Exception exception)
        {
            // Logueamos el error
            log.error(BaseServerConstants.ERROR_MESSAGE_JWT_INVALID_DESC, exception);

            // Lanzamos una excepción
            throw new IOException(BaseServerConstants.ERROR_MESSAGE_JWT_INVALID_DESC, exception);
        }
    }

    /**
     * Verifica un token propio del ecosistema Reaktor y construye la autenticación del usuario o aplicación.
     * 
     * @param jwt token propio del ecosistema Reaktor
     * @param dtoAuditoria con el objeto de auditoría
     * @return la autenticación construida, o null si no procede autenticar
     */
    private UsernamePasswordAuthenticationToken procesarTokenPropio(DtoAuditoria dtoAuditoria, String jwt)
    {
        // Inicializamos la autenticación a null
        UsernamePasswordAuthenticationToken authentication = null;

        // Parseamos y verificamos el token, obteniendo los claims
        Claims claims = this.jwtParser.parseSignedClaims(jwt).getPayload();

        // Verificamos si es una aplicación o un usuario
        if (claims.containsKey(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_EMAIL))
        {
            // Extraer info de usuario del JWT
            DtoUsuarioExtended usuario = this.obtenerUsuarioPropio(jwt, claims) ;
            
            // Creamos la lista de roles como GrantedAuthority para Spring Security
            List<GrantedAuthority> authorities = usuario.getRoles()
                                                        .stream()
                                                        .map(SimpleGrantedAuthority::new)
                                                        .collect(Collectors.toList()) ;
            
            // Creamos el objeto de autenticación
            authentication = new UsernamePasswordAuthenticationToken(usuario, null, authorities) ;

            // Rellenamos el objeto de auditoría con la información del usuario
            this.rellenarAuditoriaUsuario(dtoAuditoria, false, usuario);
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

            // Rellenamos el objeto de auditoría con la información de la aplicación
            this.rellenarAuditoriaAplicacion(dtoAuditoria, aplicacion);
        }

        // Devolvemos la autenticación
        return authentication;
    }

   /**
     * Extrae y valida el JWT, devolviendo la info de usuario propio.
     *
     * @param jwt con el JWT
     * @param claims con la información del usuario del JWT
     * @return DtoUsuarioExtended con datos del usuario propio
     */
    private DtoUsuarioExtended obtenerUsuarioPropio(String jwt, Claims claims)
    {
       // Extraemos datos de usuario
       String email           = (String) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_EMAIL);
       String cursoAcademico  = (String) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_CURSO_ACADEMICO);
       String nombre          = (String) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_NOMBRE);
       String apellidos       = (String) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_APELLIDOS);
       String departamento    = (String) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_DEPARTAMENTO);
       String fechaNacimiento = (String) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_FECHA_NACIMIENTO);

       @SuppressWarnings("unchecked")
       List<String> roles = (List<String>) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_ROLES);

       // Devolvemos el usuario con roles
       DtoUsuarioExtended dtoUsuarioExtended = new DtoUsuarioExtended() ;
       
       // Seteamos los datos del usuario
       dtoUsuarioExtended.setEmail(email);
       dtoUsuarioExtended.setCursoAcademico(cursoAcademico);
       dtoUsuarioExtended.setNombre(nombre);
       dtoUsuarioExtended.setApellidos(apellidos);
       dtoUsuarioExtended.setDepartamento(departamento);
       dtoUsuarioExtended.setFechaNacimiento(fechaNacimiento);
       dtoUsuarioExtended.setRoles(roles);
       dtoUsuarioExtended.setJwt(jwt);
       
       return dtoUsuarioExtended;
    }

   /**
    * Rellena el objeto de auditoría con la información del usuario.
    *
    * @param dtoAuditoria con el objeto de auditoría
    * @param esTokenGoogle si es un token de Google
    * @param authentication con la autenticación
    */
    private void rellenarAuditoriaUsuario(DtoAuditoria dtoAuditoria, boolean esTokenGoogle, DtoUsuarioExtended usuario)
    {
        // Seteamos los campos comunes del objeto de auditoría
        this.setearCamposComunesAuditoria(dtoAuditoria, usuario);

        // Si no es un token de Google, creamos el objeto de auditoría
        if (!esTokenGoogle)
        {
            // Le añadimos los campos específicos del usuario propio
            this.crearAuditoriaUsuarioPropio(dtoAuditoria, usuario);
        }
    }

    /**
     * Crea el objeto de auditoría para el usuario Google.
     *
     * @param usuario con el usuario
     */
    private void crearAuditoriaUsuarioPropio(DtoAuditoria dtoAuditoria, DtoUsuarioExtended usuario)
    {
        // Seteamos el tipo de evento (USUARIO)
        dtoAuditoria.setTipoEventoUsuarioAplicacion(BaseConstants.STRING_TIPO_EVENTO_USUARIO);

        // Seteamos el email del usuario
        dtoAuditoria.setEmailUsuario(usuario.getEmail());

        // Seteamos el nombre del usuario
        dtoAuditoria.setNombreUsuario(usuario.getNombre());

        // Seteamos la lista de roles
        dtoAuditoria.setRoles(usuario.getRoles());

        // Seteamos los apellidos del usuario
        dtoAuditoria.setApellidosUsuario(usuario.getApellidos());
    }

   /**
    * Setea los campos comunes del objeto de auditoría.
    *
    * @param dtoAuditoria con el objeto de auditoría
    * @param usuario con el usuario
    */
   private void setearCamposComunesAuditoria(DtoAuditoria dtoAuditoria, DtoUsuarioExtended usuario)
   {
        // Seteamos el tipo de evento (USUARIO)
        dtoAuditoria.setTipoEventoUsuarioAplicacion(BaseConstants.STRING_TIPO_EVENTO_USUARIO);

        // Seteamos el email del usuario
        dtoAuditoria.setEmailUsuario(usuario.getEmail());

        // Seteamos el nombre del usuario
        dtoAuditoria.setNombreUsuario(usuario.getNombre());
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
       String nombre         = (String) claims.get(BaseConstants.JWT_ATTR_APLICACIONES_ATTRIBUTE_NOMBRE) ;
       String cursoAcademico = (String) claims.get(BaseConstants.JWT_ATTR_APLICACIONES_ATTRIBUTE_CURSO_ACADEMICO) ;

       @SuppressWarnings("unchecked")
       List<String> roles    = (List<String>) claims.get(BaseConstants.JWT_ATTR_APLICACIONES_ATTRIBUTE_ROLES) ;

       // Devolvemos la aplicación con roles
       return new DtoAplicacion(nombre, cursoAcademico, roles) ;
    }

    /**
     * Añade los campos específicos de la aplicación al objeto de auditoría.
     *
     * @param aplicacion con la aplicación
     */
    private void rellenarAuditoriaAplicacion(DtoAuditoria dtoAuditoria, DtoAplicacion aplicacion)
    {
        // Seteamos el tipo de evento (APLICACION)
        dtoAuditoria.setTipoEventoUsuarioAplicacion(BaseConstants.STRING_TIPO_EVENTO_APLICACION);

        // Seteamos el nombre de la aplicación
        dtoAuditoria.setNombreAplicacion(aplicacion.getNombre());

        // Seteamos la lista de roles
        dtoAuditoria.setRoles(aplicacion.getRoles());
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
