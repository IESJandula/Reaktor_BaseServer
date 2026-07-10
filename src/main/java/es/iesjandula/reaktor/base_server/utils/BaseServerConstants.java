package es.iesjandula.reaktor.base_server.utils;

import java.util.regex.Pattern;

/**
 * Constantes de la aplicación base server
 */
public class BaseServerConstants
{

	/*********************************************************/
	/********************* Errores de Google *****************/
	/*********************************************************/

	/** Integer - Código de error - Email de Google no autorizado (no está en la allowlist) */
	public static final int ERROR_MESSAGE_EMAIL_GOOGLE_NOT_AUTHORIZED_CODE = 100 ;

	/** String - Descripción del error - Email de Google no autorizado (no está en la allowlist) */
	public static final String ERROR_MESSAGE_EMAIL_GOOGLE_NOT_AUTHORIZED_DESC = "Email de Google no autorizado (no está en la allowlist): ";

	/** Integer - Código de error - Token de Google inválido */
	public static final int ERROR_MESSAGE_JWT_INVALID_CODE = 101 ;

	/** String - Descripción del error - Token de Google inválido */
	public static final String ERROR_MESSAGE_JWT_INVALID_DESC = "Token de Google inválido";


	/*********************************************************/
	/************* Atributos de JWT de Google ****************/
	/*********************************************************/

	/** String - Nombre del atributo del email en el JWT de Google */
	public static final String JWT_ATTR_GOOGLE_ATTRIBUTE_EMAIL = "email";

	/** String - Nombre del atributo del nombre en el JWT de Google */
	public static final String JWT_ATTR_GOOGLE_ATTRIBUTE_NAME = "name";
	
	/*********************************************************/
	/*********************** Auditoría ***********************/
	/*********************************************************/

	/** String - Nombre de la aplicación */
	public static final String STRING_SPRING_APPLICATION_NAME = "spring.application.name";


	/*********************************************************/
	/********************* Google/Firebase *******************/
	/*********************************************************/

	/** String - Prefijo de issuer que identifican un token emitido por Google/Firebase */
	public static final String GOOGLE_ISSUER_PREFIX = "https://securetoken.google.com/";

	/** String - Issuer de Google sin HTTPS que identifica un token emitido por Google/Firebase */
	public static final String GOOGLE_ISSUER_ACCOUNTS_GOOGLE_COM = "accounts.google.com";

	/** String - Issuer de Google con HTTPS que identifica un token emitido por Google/Firebase */
	public static final String GOOGLE_ISSUER_ACCOUNTS_GOOGLE_COM_WITH_HTTPS = "https://accounts.google.com";

	/** Endpoint público con los certificados X.509 (kid -> certificado PEM) del Secure Token Service de Google */
	public static final String GOOGLE_CERTS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

	/** TTL por defecto de la caché de claves si no se puede leer el Cache-Control (1 hora) */
	public static final long TTL_POR_DEFECTO_SEGUNDOS = 3600L;

	/** Patrón para extraer max-age del header Cache-Control */
	public static final Pattern PATRON_MAX_AGE = Pattern.compile("max-age=(\\d+)");
}
