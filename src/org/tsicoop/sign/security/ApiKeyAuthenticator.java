package org.tsicoop.sign.security;

import org.tsicoop.sign.app.AppContext;

import java.util.Optional;

public interface ApiKeyAuthenticator {

    /** Returns empty if no active key matches; never throws on bad input. */
    Optional<AppContext> resolve(String rawApiKey);
}
