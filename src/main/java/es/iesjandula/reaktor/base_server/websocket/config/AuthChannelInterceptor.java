package es.iesjandula.reaktor.base_server.websocket.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.stereotype.Component;

import es.iesjandula.reaktor.base.security.service.PublicKeyGetter;
import es.iesjandula.reaktor.base.utils.BaseConstants;
import es.iesjandula.reaktor.base.utils.BaseException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;

/**
 * Interceptor que se ejecuta antes de que el servidor procese cualquier mensaje
 * WebSocket entrante.
 * 
 * Se utiliza para interceptar la conexión inicial (CONNECT) y validar que el
 * cliente envía un JWT.
 */
@Component
public class AuthChannelInterceptor implements ChannelInterceptor
{
	/** Parser JWT reutilizable */
	private JwtParser jwtParser;

	@Autowired
	private PublicKeyGetter publicKeyGetter;

	/**
	 * Inicializamos el parser una sola vez con la clave pública
	 */
	@PostConstruct
	public void init() throws BaseException
	{
		this.jwtParser = Jwts.parser().verifyWith(this.publicKeyGetter.obtenerClavePublica()).build();
	}

	@Override
	@SuppressWarnings("null")
	public Message<?> preSend(Message<?> message, MessageChannel channel)
	{

		// Obtenemos el accessor del mensaje STOMP
		StompHeaderAccessor accessor = MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);

		// Solo interceptamos cuando el cliente se conecta (CONNECT)
		if (accessor != null && accessor.getCommand() != null && accessor.getCommand().name().equals("CONNECT"))
		{

			// Obtenemos el header Authorization enviado desde el frontend
			String authHeader = accessor.getFirstNativeHeader("Authorization");

			// Validamos que exista y tenga formato Bearer
			if (authHeader == null || !authHeader.startsWith("Bearer "))
			{
				throw new IllegalArgumentException("JWT no enviado");
			}

			// Extraemos el token sin "Bearer "
			String jwt = authHeader.substring(7);

			try
			{
				// VALIDAMOS EL JWT con clave pública (igual que en REST)
				Claims claims = this.jwtParser.parseSignedClaims(jwt).getPayload();

				// Distinguimos si es usuario o aplicación
				if (claims.containsKey(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_EMAIL))
				{

					// Extraemos email del usuario
					String email = (String) claims.get(BaseConstants.JWT_ATTR_USUARIOS_ATTRIBUTE_EMAIL);

					// Guardamos el usuario autenticado en el WebSocket
					accessor.setUser(() -> email);

				} else
				{

					// Es una aplicación
					String nombreApp = (String) claims.get(BaseConstants.JWT_ATTR_APLICACIONES_ATTRIBUTE_NOMBRE);

					accessor.setUser(() -> nombreApp);
				}

			} 
			catch (Exception e)
			{
				// Si el token no es válido → cortamos conexión
				throw new IllegalArgumentException("JWT inválido");
			}
		}
		return message;
	}
}