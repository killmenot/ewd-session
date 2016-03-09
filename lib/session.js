/*

 ----------------------------------------------------------------------------
 | ewd-session: Session management using ewd-document-store                 |
 |                                                                          |
 | Copyright (c) 2016 M/Gateway Developments Ltd,                           |
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

*/

var uuid = require('node-uuid');
var defaultDocumentName = '%zewdSession';
var documentName;

var documentStore;

function init(docStore, docName) {
  documentStore = docStore;
  documentName = docName || defaultDocumentName;
  
}

// ======== Token ==================

function Token(documentStore, token, documentName) {
  documentName = documentName || defaultDocumentName;
  this.documentName = documentName;
  this.documentStore = documentStore;
  var tokenGlo = new documentStore.DocumentNode(documentName, ['sessionsByToken']);
  if (!token) token = uuid.v4();
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

function Session(documentStore, id, updateExpiry, documentName) {
  documentName = documentName || defaultDocumentName;
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

proto.next = require('./proto/session/next');
proto.updateExpiry = require('./proto/session/updateExpiry');

proto.delete = function() {
  var token = new Token(this.documentStore, this.token, this.documentName);
  token.delete();
  this.data.delete();
};

// ================================

var symbolTable = require('./proto/symbolTable');

function clearExpiredSessions(worker, documentName) {
  console.log('Checking for expired sessions');
  var sessGlo = new worker.documentStore.DocumentNode(documentName, ['session']);
  sessGlo.forEachChild(function(id) {
    var session = new Session(worker.documentStore, id, false);
    var ok = session.expired; // deletes expired ones as a side effect of checking their expiration status
    if (ok) console.log('session ' + id + ' deleted');
  });
  console.log('Finished checking sessions');
}

var garbageCollector = function garbageCollector(worker, delay, documentName) {

  delay = delay*1000 || 300000; // every 5 minutes
  documentName = documentName || '%zewdSession';

  var garbageCollector;

  worker.on('stop', function() {
    clearTimeout(garbageCollector);
    console.log('Session Garbage Collector has stopped');
  });
  
  garbageCollector = setInterval(function() {
    clearExpiredSessions(worker, documentName);
  }, delay);

  console.log('Session Garbage Collector has started in worker ' + process.pid);
}

create = function(application, timeout, updateExpiry) {
  timeout = timeout || 3600;
  application = application || 'undefined';
  var session = new Session(documentStore, null, updateExpiry, documentName);
  session.data.delete();
  var token = new Token(documentStore, null, documentName);
  token.sessionId = session.id;
  var now = Math.floor(new Date().getTime()/1000);
  timeout = timeout || 3600;
  var expiry = now + timeout;

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

module.exports = {
  init: init,
  addTo: init,
  create: create,
  uuid: uuid.v4(),
  symbolTable: symbolTable,
  garbageCollector: garbageCollector,
  authenticate: tokenAuthenticate
};
