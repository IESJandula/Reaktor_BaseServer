package es.iesjandula.reaktor.base_server.websocket.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO que representa el mensaje que envía el frontend al backend
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class WebSocketRequestDto {
    // Texto que envía el usuario
    private String pregunta;
}
