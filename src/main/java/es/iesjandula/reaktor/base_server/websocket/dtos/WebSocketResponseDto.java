package es.iesjandula.reaktor.base_server.websocket.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO que representa la respuesta del backend al frontend
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class WebSocketResponseDto {

    // Pregunta original
    private String pregunta;

    // Respuesta generada
    private String respuesta;

    // Estado del procesamiento (OK, ERROR, etc.)
    private String estado;
}
