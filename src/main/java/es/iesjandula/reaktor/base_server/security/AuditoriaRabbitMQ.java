package es.iesjandula.reaktor.base_server.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import es.iesjandula.reaktor.base.security.models.DtoAuditoria;

/**
 * Publicador de eventos de auditoría a RabbitMQ; errores silenciosos (warn), sin reintentos síncronos.
 */
@Service
public class AuditoriaRabbitMQ
{
	/** Logger de la clase */
	private static final Logger log = LoggerFactory.getLogger(AuditoriaRabbitMQ.class);

	/** Atributo - Template de RabbitMQ */
	@Autowired
	private RabbitTemplate rabbitTemplate;

	/** Atributo - Exchange de RabbitMQ */
	@Value("${reaktor.audit.exchange}")
	private String exchange;

	/** Atributo - Routing key de RabbitMQ */
	@Value("${reaktor.audit.routing-key}")
	private String routingKey;

	/**
	 * Publica el evento de forma segura.
	 * @param dtoAuditoria con el evento de auditoría
	 */
	public void publicarEvento(DtoAuditoria dtoAuditoria)
	{
		try
		{
			// Publicamos el evento de auditoría
			this.rabbitTemplate.convertAndSend(this.exchange, this.routingKey, dtoAuditoria);
		}
		catch (Exception exception)
		{
			// En caso de error, logueamos el error en warning
			log.warn("El siguiente evento de auditoría no se ha publicado:" + 
			         	" service="    					+ dtoAuditoria.getServiceName() + 
						" tipoEventoUsuarioAplicacion=" + dtoAuditoria.getTipoEventoUsuarioAplicacion() + 
						" emailUsuario="                + dtoAuditoria.getEmailUsuario() + 
						" nombreUsuario="               + dtoAuditoria.getNombreUsuario() + 
						" apellidosUsuario=" 			+ dtoAuditoria.getApellidosUsuario() + 
						" roles="            			+ dtoAuditoria.getRoles() + 
						" metodo="           			+ dtoAuditoria.getMetodo() + 
						" endpoint="         			+ dtoAuditoria.getEndpoint() + 
						" status="           			+ dtoAuditoria.getStatus() + 
						" durationMs="       			+ dtoAuditoria.getDurationMs(),
			            " exchange=" +  this.exchange + " routingKey=" + this.routingKey, 
					exception) ;
		}
	}
}
