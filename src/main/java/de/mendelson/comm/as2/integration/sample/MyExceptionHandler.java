package de.mendelson.comm.as2.integration.sample;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@Slf4j
@ControllerAdvice
public class MyExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> restErrorException(Exception e) {
        log.error(e.getMessage(), e);
        return ResponseEntity.status(500).body(e.getMessage());
    }
}
