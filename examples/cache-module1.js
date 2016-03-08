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

var sessions = require('ewd-session');

module.exports = function() {

  this.on('dbOpened', function(status) {
    console.log('Cache was opened by worker ' + process.pid + ': status = ' + JSON.stringify(status));
  });

  this.on('start', function(isFirst) {

    var connectCacheTo = require('ewd-qoper8-cache');
    connectCacheTo(this);
    sessions.init(this.documentStore);
    sessions.garbageCollector(this);

    if (isFirst) {
      var passwords = new this.documentStore.DocumentNode('ewdPasswords');
      passwords.delete();
      passwords.$('rob').value = 'secret';
    }
  });

  this.on('message', function(messageObj, send, finished) {

    if (messageObj.type === 'initiate') {
      var session = sessions.create('testApp');
      finished({
        token: session.token
      });
    }

    if (messageObj.type === 'login') {

      // user hasn't yet logged in, so set 2nd argument (loggingIn) to true
 
      var results = sessions.authenticate(messageObj.token, true);
      if (results.error) {
        finished(results);
        return;
      }
      var passwords = new this.documentStore.DocumentNode('ewdPasswords');
      var username = messageObj.credentials.username;
      var password = messageObj.credentials.password;
      if (!username || username === '') {
        finished({error: 'Missing username'});
        return;
      }
      if (!password || password === '') {
        finished({error: 'Missing password'});
        return;
      }
      if (!passwords.$(username).exists) {
        finished({error: 'Invalid username'});
        return;
      }
      if (passwords.$(username).value !== password) {
        finished({error: 'Invalid password'});
        return;
      }
      var session = results.session;
      session.authenticated = true;
      finished({
        ok: true,
        appName: session.data.$('ewd_appName').value
      });
    }
    
    finished({error: 'invalid request: ' + messageObj.type});
  });

  this.on('stop', function() {
    console.log('Connection to GT.M closed');
  });
  
};
