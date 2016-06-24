/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.web.handler.impl;

import java.util.UUID;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.web.Cookie;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.Session;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.sstore.SessionStore;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class SessionHandlerImpl implements SessionHandler {

  private static final Logger log = LoggerFactory.getLogger(SessionHandlerImpl.class);
  private static final long MAX_AGE_DESTROYED = 0;

  private final SessionStore sessionStore;
  private String sessionCookieName;
  private long sessionTimeout;
  private boolean nagHttps;
  private boolean sessionCookieSecure;
  private boolean sessionCookieHttpOnly;

  public SessionHandlerImpl(String sessionCookieName, long sessionTimeout, boolean nagHttps, boolean sessionCookieSecure, boolean sessionCookieHttpOnly, SessionStore sessionStore) {
    this.sessionCookieName = sessionCookieName;
    this.sessionTimeout = sessionTimeout;
    this.nagHttps = nagHttps;
    this.sessionStore = sessionStore;
    this.sessionCookieSecure = sessionCookieSecure;
    this.sessionCookieHttpOnly = sessionCookieHttpOnly;
  }

  @Override
  public SessionHandler setSessionTimeout(long timeout) {
    this.sessionTimeout = timeout;
    return this;
  }

  @Override
  public SessionHandler setNagHttps(boolean nag) {
    this.nagHttps = nag;
    return this;
  }

  @Override
  public SessionHandler setCookieSecureFlag(boolean secure) {
    this.sessionCookieSecure = secure;
    return this;
  }

  @Override
  public SessionHandler setCookieHttpOnlyFlag(boolean httpOnly) {
    this.sessionCookieHttpOnly = httpOnly;
    return this;
  }

  @Override
  public SessionHandler setSessionCookieName(String sessionCookieName) {
    this.sessionCookieName = sessionCookieName;
    return this;
  }

  @Override
  public void handle(RoutingContext context) {
    context.response().ended();

    if (nagHttps) {
      String uri = context.request().absoluteURI();
      if (!uri.startsWith("https:")) {
        log.warn("Using session cookies without https could make you susceptible to session hijacking: " + uri);
      }
    }

    context.setSessionHandler(this);

    context.addHeadersEndHandler(v -> {
      Session session = context.session(false);
      if (session != null) {
        storeSession(context);
      }
    });

    context.next();
  }

  @Override
  public void createSession(RoutingContext context) {
    // Look for existing session cookie
    Cookie cookie = context.getCookie(sessionCookieName);
    if (cookie != null && cookie.getMaxAge() != MAX_AGE_DESTROYED) {
      // Look up session
      String sessionID = cookie.getValue();
      // ***FIX*** Getting the session needs to be synchronous but adding a latch here creates a deadlock?
      doGetSession(context.vertx(), System.currentTimeMillis(), sessionID, res -> {
        if (res.succeeded()) {
          Session session = res.result();
          if (session != null) {
            context.setSession(session);
            session.setAccessed();
          } else {
            // Cannot find session - either it timed out, or was explicitly destroyed at the server side on a
            // previous request.
            // Either way, we create a new one.
            createNewSession(context);
          }
        } else {
          createNewSession(context);
        }
      });
    } else {
      createNewSession(context);
    }
  }

  @Override
  public void destroySession(RoutingContext context) {
    Session session = context.session(false);
    if (session != null) {
      sessionStore.delete(session.id(), res -> {
        if (res.failed()) {
          log.error("Failed to delete session", res.cause());
        }
      });
      context.setSession(null);

      Cookie cookie = Cookie.cookie(sessionCookieName, session.id());
      cookie.setPath("/");
      cookie.setSecure(sessionCookieSecure);
      cookie.setHttpOnly(sessionCookieHttpOnly);
      cookie.setMaxAge(MAX_AGE_DESTROYED);
      context.addCookie(cookie);
    }
  }

  private void storeSession(RoutingContext context) {
    final int currentStatusCode = context.response().getStatusCode();
    // Store the session (only and only if there was no error)
    if (currentStatusCode >= 200 && currentStatusCode < 400) {
      Session session = context.session();
      session.setAccessed();
      sessionStore.put(session, res -> {
        if (res.failed()) {
          log.error("Failed to store session", res.cause());
        }
      });
    } else {
      // don't send a cookie if status is not 2xx or 3xx
      context.removeCookie(sessionCookieName);
    }
  }

  private String getNextId() {
    return UUID.randomUUID().toString();
  }

  private void createNewSession(RoutingContext context) {
    Session session = sessionStore.createSession(context, getNextId(), sessionTimeout);
    context.setSession(session);
    Cookie cookie = Cookie.cookie(sessionCookieName, session.id());
    cookie.setPath("/");
    cookie.setSecure(sessionCookieSecure);
    cookie.setHttpOnly(sessionCookieHttpOnly);
    // Don't set max age - it's a session cookie
    context.addCookie(cookie);
  }

  private void doGetSession(Vertx vertx, long startTime, String sessionID, Handler<AsyncResult<Session>> resultHandler) {
    sessionStore.get(sessionID, res -> {
      if (res.succeeded()) {
        if (res.result() == null) {
          // Can't find it so retry. This is necessary for clustered sessions as it can take sometime for the session
          // to propagate across the cluster so if the next request for the session comes in quickly at a different
          // node there is a possibility it isn't available yet.
          long retryTimeout = sessionStore.retryTimeout();
          if (retryTimeout > 0 && System.currentTimeMillis() - startTime < retryTimeout) {
            vertx.setTimer(5, v -> doGetSession(vertx, startTime, sessionID, resultHandler));
            return;
          }
        }
      }
      resultHandler.handle(res);
    });
  }

}
