package es.iesjandula.reaktor.base_server.security;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import es.iesjandula.reaktor.base_server.utils.BaseServerConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.Jwts;

/**
 * Verificador de tokens de Google (Firebase Authentication / Secure Token Service).
 * <p>
 * En lugar de depender del SDK de Firebase Admin (que obligaría a TODOS los servidores que usan BaseServer a
 * inicializar una {@code FirebaseApp} con credenciales), este verificador valida la firma del token de Google
 * directamente contra las claves públicas X.509 que Google publica para su servicio {@code securetoken}. Esto solo
 * requiere una llamada HTTP a un endpoint público, sin secretos.
 * </p>
 * <p>
 * Las claves se cachean en memoria y se refrescan cuando expira la caché (según el {@code Cache-Control} de la
 * respuesta) o cuando llega un token firmado con un {@code kid} desconocido.
 * </p>
 */
@Component
public class GoogleTokenVerifier
{
    /** Logger de la clase */
    private static final Logger log = LoggerFactory.getLogger(GoogleTokenVerifier.class);

    /**
     * ID del proyecto de Firebase (opcional). Si se define, se valida además el issuer exacto y la audiencia (aud)
     * del token. Si se deja vacío, solo se valida que el issuer tenga el prefijo de Google.
     */
    @Value("${reaktor.google.projectId:}")
    private String googleProjectId;

    /** Cliente HTTP (Java 17) para descargar las claves públicas de Google */
    private final HttpClient httpClient = HttpClient.newHttpClient();

    /** ObjectMapper para parsear la respuesta JSON con los certificados */
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** Caché de claves públicas indexadas por kid */
    private volatile Map<String, Key> clavesPublicasPorKid = new HashMap<String, Key>();

    /** Instante (millis) en el que expira la caché de claves */
    private volatile long expiracionCacheMillis = 0L;

    /**
     * Verifica la firma y las claims básicas de un token de Google y devuelve sus claims.
     *
     * @param jwt token de Google (JWS RS256)
     * @return las claims del token verificado
     * @throws Exception si la firma no es válida, el token ha expirado, el issuer/aud no cuadra o falta la clave
     */
    public Claims verificarToken(String jwt) throws Exception
    {
        // Localizador de la clave pública en función del 'kid' de la cabecera del token
        Locator<Key> localizadorClaves = new Locator<Key>()
        {
            @Override
            public Key locate(Header header)
            {
                // Obtenemos el 'kid' de la cabecera del token
                Object kid = header.get("kid");

                // Si el 'kid' es nulo, devolvemos null, y si no, obtenemos la clave pública asociada a ese 'kid'
                return kid == null ? null : GoogleTokenVerifier.this.obtenerClavePorKid(kid.toString());
            }
        };

        // jjwt valida la firma (con la clave localizada por kid) y la expiración automáticamente
        Claims claims = Jwts.parser()
                            .keyLocator(localizadorClaves)
                            .build()
                            .parseSignedClaims(jwt)
                            .getPayload();

        // Validación defensiva del issuer: debe ser el del Secure Token Service de Google
        String issuer = claims.getIssuer();

        // Si el issuer es nulo o no comienza con el prefijo de Google, lanzamos una excepción
        if (issuer == null || !issuer.startsWith(BaseServerConstants.GOOGLE_ISSUER_PREFIX))
        {
            throw new SecurityException("El issuer del token de Google no es válido: " + issuer);
        }

        // Si se ha configurado el projectId, exigimos issuer exacto y audiencia coincidente
        if (this.googleProjectId != null && !this.googleProjectId.isBlank())
        {
            // Si el issuer no coincide con el projectId configurado, lanzamos una excepción
            if (!issuer.equals(BaseServerConstants.GOOGLE_ISSUER_PREFIX + this.googleProjectId))
            {
                throw new SecurityException("El issuer del token de Google no corresponde al projectId configurado") ;
            }

            // Obtenemos la audiencia del token (que es el projectId)
            Set<String> audiencia = claims.getAudience();

            // Si la audiencia es nula o no contiene el projectId configurado, lanzamos una excepción
            // Esto es para asegurar que el token se ha emitido para el proyecto configurado
            if (audiencia == null || !audiencia.contains(this.googleProjectId))
            {
                throw new SecurityException("La audiencia (aud) del token de Google no corresponde al projectId configurado") ;
            }
        }

        return claims;
    }

    /**
     * Devuelve la clave pública asociada a un kid, refrescando la caché si ha expirado o si el kid es desconocido.
     *
     * @param kid identificador de la clave (cabecera del token)
     * @return la clave pública, o null si no se encuentra
     */
    private Key obtenerClavePorKid(String kid)
    {
        if (kid == null)
        {
            return null;
        }

        Map<String, Key> clavesActuales = this.clavesPublicasPorKid;

        // Refrescamos si la caché ha caducado o si no conocemos ese kid (posible rotación de claves)
        if (System.currentTimeMillis() > this.expiracionCacheMillis || !clavesActuales.containsKey(kid))
        {
            // Refrescamos las claves públicas de Google
            this.refrescarClaves();

            // Actualizamos la caché de claves
            clavesActuales = this.clavesPublicasPorKid;
        }

        // Devolvemos la clave pública asociada al kid
        return clavesActuales.get(kid);
    }

    /**
     * Descarga los certificados X.509 de Google y reconstruye la caché de claves públicas.
     */
    private synchronized void refrescarClaves()
    {
        try
        {
            // Petición HTTP al endpoint público de certificados de Google
            HttpRequest httpRequest = HttpRequest.newBuilder()
                                                 .uri(URI.create(BaseServerConstants.GOOGLE_CERTS_URL))
                                                 .GET()
                                                 .build();

            // Enviamos la petición HTTP y obtenemos la respuesta
            HttpResponse<String> httpResponse = this.httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            // Si el código de estado no es 200, logueamos el error y devolvemos
            if (httpResponse.statusCode() != 200)
            {
                log.error("No se pudieron obtener las claves públicas de Google. Código HTTP: {}", httpResponse.statusCode());
                return;
            }

            // La respuesta es un objeto JSON { kid: "-----BEGIN CERTIFICATE----- ..." }
            JsonNode raiz = this.objectMapper.readTree(httpResponse.body());

            // Creamos una nueva caché de claves
            Map<String, Key> nuevasClaves = new HashMap<>();

            // Creamos un factor de certificados X.509
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            // Iteramos sobre los campos del objeto JSON
            Iterator<Map.Entry<String, JsonNode>> iterador = raiz.fields();

            // Mientras haya campos, procesamos cada uno
            while (iterador.hasNext())
            {
                // Obtenemos el campo actual
                Map.Entry<String, JsonNode> entrada = iterador.next();

                // Obtenemos el 'kid' y el certificado del campo actual
                String kid          = entrada.getKey();
                String certificado  = entrada.getValue().asText();

                // Parseamos el certificado X.509 (PEM) y extraemos su clave pública
                X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(
                        new ByteArrayInputStream(certificado.getBytes(StandardCharsets.UTF_8)));

                // Añadimos la clave pública a la nueva caché
                nuevasClaves.put(kid, x509Certificate.getPublicKey());
            }

            // Publicamos la nueva caché y calculamos su expiración
            this.clavesPublicasPorKid = nuevasClaves;
            this.expiracionCacheMillis = System.currentTimeMillis() + (this.obtenerTtlSegundos(httpResponse) * 1000L);
        }
        catch (Exception exception)
        {
            log.error("Error al refrescar las claves públicas de Google", exception);
        }
    }

    /**
     * Obtiene el TTL (segundos) de la caché a partir del header Cache-Control de la respuesta, o un valor por defecto.
     *
     * @param httpResponse respuesta HTTP con los certificados
     * @return TTL en segundos
     */
    private long obtenerTtlSegundos(HttpResponse<String> httpResponse)
    {
        return httpResponse.headers()
                           .firstValue("cache-control")
                           .map(cacheControl ->
                           {
                               Matcher matcher = BaseServerConstants.PATRON_MAX_AGE.matcher(cacheControl);

                               return matcher.find() ? Long.parseLong(matcher.group(1)) : BaseServerConstants.TTL_POR_DEFECTO_SEGUNDOS;
                           })
                           .orElse(BaseServerConstants.TTL_POR_DEFECTO_SEGUNDOS);
    }
}
