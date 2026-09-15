package org.tsicoop.sign.service.v1;

/** Thrown when a template's HTML/Mustache content itself is malformed — a client input problem (bad template), not a server fault. */
public class TemplateRenderException extends Exception {

    public TemplateRenderException(String message) {
        super(message);
    }

    public TemplateRenderException(String message, Throwable cause) {
        super(message, cause);
    }
}
