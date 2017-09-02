/*

 ----------------------------------------------------------------------------
 | ewd-session: Session management using ewd-document-store                 |
 |                                                                          |
 | Copyright (c) 2016-17 M/Gateway Developments Ltd,                        |
 | Reigate, Surrey UK.                                                      |
 | All rights reserved.                                                     |
 |                                                                          |
 | http://www.mgateway.com                                                  |
 | Email: rtweed@mgateway.com                                               |
 |                                                                          |
 |                                                                          |
 | Licensed under the Apache License, Version 2.0 (the "License");          |
 | you may not use this file except in compliance with the License.         |
 | You may obtain a copy of the License at                                  |
 |                                                                          |
 |     http://www.apache.org/licenses/LICENSE-2.0                           |
 |                                                                          |
 | Unless required by applicable law or agreed to in writing, software      |
 | distributed under the License is distributed on an "AS IS" BASIS,        |
 | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. |
 | See the License for the specific language governing permissions and      |
 |  limitations under the License.                                          |
 ----------------------------------------------------------------------------

  1 September 2017

*/

var uuid = require('uuid/v4');
var jwt = require('jwt-simple');

var defaultDocumentName = '%zewdSession';
var documentName;

var documentStore;

function init(docStore, docName) {
  documentStore = docStore;
  documentName = docName || defaultDocumentName;
  
}

// ======== Token ==================

function Token(documentStore, token, docName) {
  documentName = docName || documentName || defaultDocumentName;
  this.documentName = documentName;
  this.documentStore = documentStore;
  var tokenGlo = new documentStore.DocumentNode(documentName, ['sessionsByToken']);
  if (!token) token = uuid();
  this.value = token;
  this.data = tokenGlo.$(token);
}

var proto = Token.prototype;

Object.defineProperty(proto, 'session', {
  get: function() {
    var session = new Session(this.documentStore, this.sessionId, false, this.documentName);
    if (!session.exists) return false;
    if (session.expired) return false;
    return session;
  }
});

Object.defineProperty(proto, 'sessionId', require('./proto/token/sessionId'));
Object.defineProperty(proto, 'exists', require('./proto/token/exists'));

proto.delete = require('./proto/token/delete');


// ===== Session =========================

function Session(documentStore, id, updateExpiry, docName) {
  documentName = docName || documentName || defaultDocumentName;
  this.documentName = documentName;
  this.documentStore = documentStore;
  if (id) {
    this.id =id;
  }
  else {
    this.id = this.next();
  }
  this.data = new documentStore.DocumentNode(documentName, ['session', this.id]);
  if (updateExpiry !== false) this.updateExpiry(); // will be deleted if expired already
}

proto = Session.prototype;

Object.defineProperty(proto, 'exists', require('./proto/session/exists'));
Object.defineProperty(proto, 'token', require('./proto/session/token'));
Object.defineProperty(proto, 'expired', require('./proto/session/expired'));
Object.defineProperty(proto, 'authenticated', require('./proto/session/authenticated'));
Object.defineProperty(proto, 'expiryTime', require('./proto/session/expiryTime'));
Object.defineProperty(proto, 'application', require('./proto/session/application'));
Object.defineProperty(proto, 'timeout', require('./proto/session/timeout'));
Object.defineProperty(proto, 'allowedServices', require('./proto/session/allowedServices'));
Object.defineProperty(proto, 'socketId', require('./proto/session/socketId'));
Object.defineProperty(proto, 'ipAddress', require('./proto/session/ipAddress'));
Object.defineProperty(proto, 'jwt', require('./proto/session/jwt'));
Object.defineProperty(proto, 'jwtSecret', require('./proto/session/jwtSecret'));

proto.next = require('./proto/session/next');
proto.updateExpiry = require('./proto/session/updateExpiry');
proto.allowService = require('./proto/session/allowService');
proto.disallowService = require('./proto/session/disallowService');
proto.sendToSocket = require('./proto/session/sendToSocket');
proto.createJWT = require('./proto/session/createJWT');
proto.updateJWT = require('./proto/session/updateJWT');

proto.delete = function() {
  var token = new Token(this.documentStore, this.token, this.documentName);
  token.delete();
  this.data.delete();
};

// ================================

var symbolTable = require('./proto/symbolTable');

function clearExpiredSessions(worker) {
  var docName = documentName || defaultDocumentName;
  console.log(process.pid + ': Checking for expired sessions in ' + docName);
  var sessGlo = new worker.documentStore.DocumentNode(docName, ['session']);
  sessGlo.forEachChild(function(id) {
    var session = new Session(worker.documentStore, id, false);
    var ok = session.expired; // deletes expired ones as a side effect of checking their expiration status
    if (ok) console.log('session ' + id + ' deleted');
  });
  console.log('Finished checking sessions');
}

var garbageCollector = function garbageCollector(worker, delay) {

  delay = delay*1000 || 300000; // every 5 minutes
  var garbageCollector;

  worker.on('stop', function() {
    // thanks to Ward De Backer for bug fix here:
    clearInterval(garbageCollector);
    console.log('Session Garbage Collector has stopped');
  });
  
  garbageCollector = setInterval(function() {
    clearExpiredSessions(worker);
  }, delay);

  console.log('Session Garbage Collector has started in worker ' + process.pid);
}

create = function(application, timeout, updateExpiry) {
  var jwtPayload;
  if (typeof application === 'object') {
    timeout = application.timeout;
    updateExpiry = application.updateExpiry;
    jwtPayload = application.jwtPayload;  // if defined, it should contain the payload
    application = application.application;
  }
  timeout = timeout || 3600;
  application = application || 'undefined';
  var session = new Session(documentStore, null, updateExpiry, documentName);
  session.data.delete();
  var token = new Token(documentStore, null, documentName);
  token.sessionId = session.id;
  var now = Math.floor(new Date().getTime()/1000);
  timeout = timeout || 3600;
  var expiry = now + timeout;

  var jwtToken;
  var jwtSecret;

  if (jwtPayload) {
    jwtPayload.exp = expiry;
    jwtPayload.iat = now;
    jwtPayload.iss = 'qewd:' + application;
    jwtPayload.jti = token.value + '.' + now;
    jwtSecret = uuid();
    jwtToken = jwt.encode(jwtPayload, jwtSecret);
  }

  var params = {
    'ewd-session': {
      token: token.value,
      id: session.id,
      timeout: timeout,
      expiry: expiry,
      application: application,
      authenticated: false
    }
  };

  if (jwtPayload) {
    params['ewd-session'].jwt = {
      secret: jwtSecret,
      token: jwtToken
    };
  }

  session.data.setDocument(params);
  return session;
}

function tokenAuthenticate(token, loggingIn) {
  if (!token) return {
    error: 'Missing authorization header',
    status: {
      code: 403,
      text: 'Forbidden'
    }
  };
  var session = new Token(documentStore, token, documentName).session;
  if (!session.exists) return {
    error: 'Invalid token or session expired',
    status: {
      code: 403,
      text: 'Forbidden'
    }
  };
  if (session.expired) return {
    error: 'Session expired',
    status: {
      code: 403,
      text: 'Forbidden'
    }
  };
  if (loggingIn === 'noCheck') {
    return {session: session};
  }
  if (loggingIn === true) {
    if (session.authenticated) return {
      error: 'User already logged in',
      status: {
      code: 403,
      text: 'Forbidden'
      }
    };
  }
  else {
    if (!session.authenticated) return {
      error: 'User has not logged in',
      status: {
      code: 403,
      text: 'Forbidden'
      }
    };
    session.updateExpiry();
  }
  return {session: session};
}

function authenticateByJWT(jwtToken, loggingIn) {
  try {
    var payload = jwt.decode(jwtToken, null, true);
  }
  catch(err) {
    return {
      error: 'Invalid JWT: ' + err,
      status: {
        code: 403,
        text: 'Forbidden'
      }
    };
  }
  if (!payload || !payload.jti || payload.jti === '') {
    return {
      error: 'Missing or empty QEWD token',
      status: {
        code: 403,
        text: 'Forbidden'
      }
    };
  }
  
  var qewdToken = payload.jti.split('.')[0];
  var status = tokenAuthenticate(qewdToken, loggingIn);
  if (status.error) return status;

  // try re-encoding the JWT and check it's identical

  var secret = status.session.jwtSecret;
  var token = jwt.encode(payload, secret);
  //console.log('** incoming JWT: ' +  jwtToken);
  //console.log('** re-encoded  : ' +  token);
  
  if (token !== jwtToken) {
    return {
      error: 'Invalid JWT',
      status: {
        code: 403,
        text: 'Forbidden'
      }
    };
  }
  status.payload = payload;
  return status;
}

function httpAuthenticate(httpHeaders, credentials) {
  var cookie = httpHeaders.cookie;
  var authorization = httpHeaders.authorization;

  if (!cookie && !authorization) {
    return {
      error: 'Missing Authorization or Cookie Header',
      status: {
        code: 403,
        text: 'Forbidden'
      }
    };
  }

  var credentials = credentials || {};
  if (!credentials.authorization) credentials.authorization = 'QEWD token';
  if (!credentials.cookie) credentials.cookie = 'QEWDTOKEN';

  var token;

  if (authorization) {
    // authorization, if present, over-rides cookie
    token = authorization.split(credentials.authorization + '=')[1];
  }
  else {
    var pieces = cookie.split(';');
    pieces.forEach(function(piece) {
      if (piece.indexOf(credentials.cookie) !== -1) {
        token = piece.split(credentials.cookie + '=')[1];
      }
    });
  }

  if (!token || token === '') {
    return {
      error: 'Missing or Empty QEWD Session Token',
      status: {
        code: 403,
        text: 'Forbidden'
      }
    };
  }

  return tokenAuthenticate(token, 'noCheck');
}

function authenticateRestRequest(req, finished, bearer, loggingIn) {
  var auth = req.headers.authorization;
  if (!auth) {
    finished({error: 'Authorization header missing'});
    return false;
  }
  var token;
  if (bearer === false) {
    token = auth;
  }
  else {
    var pieces = auth.split('Bearer ');
    if (pieces.length !== 2) {
      finished({error: 'Authorization header invalid - expected format: Bearer {{token}}'});
      return false;
    }
    token = pieces[1];
  }
  var status = tokenAuthenticate(token, loggingIn);
  if (status.error) {
    finished(status);
    return false;
  }
  req.session = status.session;
  return true;
}

function getActiveSessions() {
  var sessions = [];
  var sessGlo = new documentStore.DocumentNode(documentName, ['session']);
  sessGlo.forEachChild(function(id) {
    var session = new Session(documentStore, id, false);
    if (!session.expired) sessions.push(session);
  });
  return sessions;
}

function getSessionByToken(token) {
  if (!token || token === '') return;
  var id = new documentStore.DocumentNode(documentName, ['sessionsByToken', token]).value;
  if (id === '') return;
  var session = new Session(documentStore, id, false);
  if (session.expired) return;
  return session;
}

module.exports = {
  init: init,
  addTo: init,
  create: create,
  uuid: uuid(),
  symbolTable: symbolTable,
  garbageCollector: garbageCollector,
  authenticate: tokenAuthenticate,
  authenticateByJWT, authenticateByJWT,
  httpAuthenticate: httpAuthenticate,
  authenticateRestRequest: authenticateRestRequest,
  active: getActiveSessions,
  byToken: getSessionByToken
};
