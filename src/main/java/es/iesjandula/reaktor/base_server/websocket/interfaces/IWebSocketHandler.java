package es.iesjandula.reaktor.base_server.websocket.interfaces;

import es.iesjandula.reaktor.base_server.websocket.dtos.WebSocketRequestDto;
import es.iesjandula.reaktor.base_server.websocket.dtos.WebSocketResponseDto;

/**
 * Interfaz para que cada microservicio implemente su lógica WebSocket.
 * 
 * Permite que BaseServer sea reutilizable sin saber qué hace cada servicio.
 */
public interface IWebSocketHandler {

    /**
     * Método que procesa un mensaje WebSocket.
     * 
     * @param request mensaje recibido del frontend
     * @return respuesta que se enviará al cliente
     */
    WebSocketResponseDto procesar(WebSocketRequestDto request);
}