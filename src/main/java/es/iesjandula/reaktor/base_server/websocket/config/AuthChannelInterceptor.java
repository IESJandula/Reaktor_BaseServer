package es.iesjandula.reaktor.base_server.websocket.config;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.stereotype.Component;

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

	@Override
	public Message<?> preSend(Message<?> message, MessageChannel channel)
	{

		// Obtenemos el accesor del mensaje STOMP
		StompHeaderAccessor accessor = MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);

		// Comprobamos que el mensaje es de tipo CONNECT (inicio de conexión)
		if (accessor != null && "CONNECT".equals(accessor.getCommand().name()))
		{

			// Obtenemos el header Authorization enviado por el frontend
			String authHeader = accessor.getFirstNativeHeader("Authorization");

			// Validamos que el token exista y tenga formato Bearer
			if (authHeader == null || !authHeader.startsWith("Bearer "))
			{
				throw new IllegalArgumentException("JWT no enviado");
			}

			// Extraemos el token quitando "Bearer "
			String token = authHeader.replace("Bearer ", "");

			// Guardamos el token como usuario autenticado
			// (no se valida aquí, solo se pasa al backend)
			accessor.setUser(() -> token);
		}

		// Devolvemos el mensaje para que continúe el flujo
		return message;
	}
}