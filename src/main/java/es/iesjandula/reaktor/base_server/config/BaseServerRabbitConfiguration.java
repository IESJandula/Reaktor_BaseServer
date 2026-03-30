package es.iesjandula.reaktor.base_server.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Configura el RabbitTemplate para serializar DTOs a JSON (Jackson).
 */
@Configuration
public class BaseServerRabbitConfiguration
{
	/** Logger de la clase */
	private static final Logger log = LoggerFactory.getLogger(BaseServerRabbitConfiguration.class);
	
	/**
	 * Configura el MessageConverter para serializar DTOs a JSON (Jackson).
	 * @param objectMapper ObjectMapper para serializar DTOs a JSON
	 * @return MessageConverter para serializar DTOs a JSON
	 */
	@Bean
	@SuppressWarnings("null")
	public MessageConverter rabbitMessageConverter(ObjectMapper objectMapper)
	{
		// Logueamos la configuración
		log.info("Configurando MessageConverter para serializar DTOs a JSON (Jackson)");

		// Creamos el MessageConverter
		return new Jackson2JsonMessageConverter(objectMapper);
	}

	/**
	 * Configura el RabbitTemplate para serializar DTOs a JSON (Jackson).
	 * @param connectionFactory ConnectionFactory para la conexión a RabbitMQ
	 * @param rabbitMessageConverter MessageConverter para serializar DTOs a JSON
	 * @return RabbitTemplate para serializar DTOs a JSON
	 */
	@Bean
	@SuppressWarnings("null")
	public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory, MessageConverter rabbitMessageConverter)
	{
		// Logueamos la configuración
		log.info("Configurando RabbitTemplate para serializar DTOs a JSON (Jackson)");

		// Creamos el RabbitTemplate y lo configuramos
		RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);

		// Configuramos el MessageConverter
		rabbitTemplate.setMessageConverter(rabbitMessageConverter);

		// Devolvemos el RabbitTemplate configurado
		return rabbitTemplate;
	}
}