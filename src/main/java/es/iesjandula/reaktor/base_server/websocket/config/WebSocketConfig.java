package es.iesjandula.reaktor.base_server.websocket.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * Configuración GLOBAL de WebSocket para todos los microservicios.
 * 
 * Define: - Broker de mensajes - Endpoint de conexión - Seguridad (interceptor)
 */
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer
{

	// Inyectamos el interceptor de seguridad
	@Autowired
	private AuthChannelInterceptor authChannelInterceptor;

	@Value("${spring.application.name}")
	private String applicationName;

	/**
	 * Configuración del broker de mensajes
	 */
	@Override
	@SuppressWarnings("null")
	public void configureMessageBroker(MessageBrokerRegistry config)
	{

		// Canal donde el backend envía mensajes al frontend
		config.enableSimpleBroker("/topic", "/queue");
		config.setUserDestinationPrefix("/user");

		// Prefijo para mensajes enviados desde el cliente
		config.setApplicationDestinationPrefixes("/app");
	}

	/**
	 * Endpoint de conexión WebSocket
	 */
	@Override
	@SuppressWarnings("null")
	public void registerStompEndpoints(StompEndpointRegistry registry)
	{
		// Construye el path dinámicamente: /printers/ws, /bookings/ws, etc.
		String endpoint = "/" + applicationName + "/ws";
			
		registry.addEndpoint(endpoint)
				.setAllowedOriginPatterns("*");
	}

	/**
	 * Aquí se añade el interceptor de seguridad
	 */
	@Override
	@SuppressWarnings("null")
	public void configureClientInboundChannel(ChannelRegistration registration)
	{
		registration.interceptors(authChannelInterceptor);
	}
}