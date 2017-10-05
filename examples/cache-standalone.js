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

// Start using:
// $ node examples/cache-standalone.js
// You may need to run this as sudo due to Cache permissions

var DocumentStore = require('ewd-document-store');
var Cache = require('cache').Cache;
var sessions = require('ewd-session');
var db = new Cache();

console.log('db: ' + JSON.stringify(db));

// Change these parameters to match your Cache system:
var ok = db.open({
  path: '/opt/cache/mgr',
  username: '_SYSTEM',
  password: 'SYS',
  namespace: 'USER'
});

console.log('ok: ' + JSON.stringify(ok));

var documentStore = new DocumentStore(db);

documentStore.on('beforeSet', function (obj) {
  console.log('beforeSet: ' + JSON.stringify(obj));
});

documentStore.on('afterSet', function (obj) {
  console.log('afterSet: ' + JSON.stringify(obj));
});

documentStore.on('beforeDelete', function (obj) {
  console.log('beforeDelete: ' + JSON.stringify(obj));
});

documentStore.on('afterDelete', function (obj) {
  console.log('afterDelete: ' + JSON.stringify(obj));
});

console.log('version: ' + documentStore.db.version());

sessions.addTo(documentStore);

var session = sessions.create('testApp');
console.log('id = ' + session.id);
console.log('token: ' + session.token);

var results = sessions.authenticate(session.token, 'noCheck');
console.log('results: ' + JSON.stringify(results));
console.log('token for session : ' + results.session.id + ': ' + results.session.token);
console.log('application : ' + results.session.application);
console.log('session data: ' + JSON.stringify(results.session.data.getDocument()));

db.close();
