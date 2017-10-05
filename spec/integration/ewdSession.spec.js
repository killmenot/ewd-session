'use strict';

require('dotenv').config();

var sessions = require('../../');
var Cache = require('cache').Cache;
var DocumentStore = require('ewd-document-store');
var qoper8 = require('ewd-qoper8');

describe('integration/ewd-session: ', function () {
  var db;
  var documentStore;

  beforeAll(function () {
    db = new Cache();
    documentStore = new DocumentStore(db);

    // save current working directory
    var cwd = process.cwd();

    db.open({
      path: process.env.CACHE_MGR_PATH || '/opt/cache/mgr',
      username: process.env.CACHE_USERNAME || '_SYSTEM',
      password: process.env.CACHE_PASSWORD || 'SYS',
      namespace: process.env.CACHE_NAMESPACE || 'USER'
    });

    // reset working directory
    process.chdir(cwd);

    sessions.init(documentStore);
  });

  afterAll(function () {
    db.close();
  });

  afterEach(function () {
    var documentNode = new documentStore.DocumentNode('%zewdSession');
    documentNode.delete();
  });

  describe('#authentcate', function () {
    it('should authenticate by token with noCheck' , function () {
      var application = 'testApp10';
      var session = sessions.create(application);

      var results = sessions.authenticate(session.token, 'noCheck');

      expect(results.error).toBeUndefined();
      expect(results.session).toBeDefined();
    });

    it('should return missing authorization header error', function () {
      var application = 'testApp11';
      sessions.create(application);

      var results = sessions.authenticate('', 'noCheck');

      expect(results.error).toBe('Missing authorization header');
      expect(results.status.code).toBe(403);
      expect(results.status.text).toBe('Forbidden');
    });

    it('should return invalid token or session expired error', function () {
      var application = 'testApp12';
      var session = sessions.create(application);
      var token = session.token;

      session.delete();

      var results = sessions.authenticate(token, 'noCheck');

      expect(results.error).toBe('Invalid token or session expired');
      expect(results.status.code).toBe(403);
      expect(results.status.text).toBe('Forbidden');
    });

    it('should return user already logged in error', function () {
      var application = 'testApp13';
      var session = sessions.create(application);

      session.authenticated = true;

      var results = sessions.authenticate(session.token, true);

      expect(results.error).toBe('User already logged in');
      expect(results.status.code).toBe(403);
      expect(results.status.text).toBe('Forbidden');
    });

    it('should return user has not logged in error', function () {
      var application = 'testApp14';
      var session = sessions.create(application);

      var results = sessions.authenticate(session.token, false);

      expect(results.error).toBe('User has not logged in');
      expect(results.status.code).toBe(403);
      expect(results.status.text).toBe('Forbidden');
    });

    it('should authenticate and update token expiration time', function () {
      var application = 'testApp15';
      var session = sessions.create(application);

      var expiryTime = new Date().getTime() / 1000 + 1800;
      session.expiryTime = expiryTime;
      session.authenticated = true;

      var results = sessions.authenticate(session.token, false);

      expect(results.session.expiryTime).toBeGreaterThan(expiryTime);
    });
  });

  describe('#authenticateByJWT', function () {
    it('should authenticate by jwt token with noCheck' , function () {
      var application = {
        application: 'testApp20',
        jwtPayload: {
          foo: 'bar',
          bar: 'baz'
        }
      };
      var session = sessions.create(application);

      var results = sessions.authenticateByJWT(session.jwt, 'noCheck');

      expect(results.error).toBeUndefined();
      expect(results.session).toBeDefined();
      expect(results.payload).toEqual(
        jasmine.objectContaining({
          iss: 'qewd:testApp20',
          foo: 'bar',
          bar: 'baz'
        })
      );
    });

    it('should be able to createJwt payload and authenticate by jwt token', function () {
      var application = 'testApp21';
      var session = sessions.create(application);
      var payload = {
        foo: 'bar'
      };

      var jwtToken = session.createJWT(payload);

      var results = sessions.authenticateByJWT(jwtToken, 'noCheck');

      expect(results.error).toBeUndefined();
      expect(results.session).toBeDefined();
      expect(results.payload).toEqual(
        jasmine.objectContaining({
          iss: 'qewd:testApp21',
          foo: 'bar'
        })
      );
    });

    it('should be able to updateJwt payload and authenticate by jwt token', function () {
      var application = 'testApp22';
      var session = sessions.create(application);

      var payload = {
        foo: 'bar'
      };
      session.createJWT(payload);

      var newPayload = {
        bar: 'baz'
      };
      session.updateJWT(newPayload);

      var results = sessions.authenticateByJWT(session.jwt, 'noCheck');

      expect(results.error).toBeUndefined();
      expect(results.session).toBeDefined();
      expect(results.payload).toEqual(
        jasmine.objectContaining({
          iss: 'qewd:testApp22',
          foo: 'bar',
          bar: 'baz'
        })
      );
    });
  });

  describe('#httpAuthenticate', function () {
    it('should authenticate by authorization header' , function () {
      var application = 'testApp30';
      var session = sessions.create(application);

      var httpHeaders = {
        authorization: 'QEWD token=' + session.token
      };

      var results = sessions.httpAuthenticate(httpHeaders);

      expect(results.error).toBeUndefined();
      expect(results.session).toBeDefined();
    });

    it('should authenticate by custom authorization header' , function () {
      var application = 'testApp31';
      var session = sessions.create(application);

      var httpHeaders = {
        authorization: '$foo$=' + session.token
      };
      var credentials = {
        authorization: '$foo$'
      };

      var results = sessions.httpAuthenticate(httpHeaders, credentials);

      expect(results.error).toBeUndefined();
      expect(results.session).toBeDefined();
    });

    it('should authenticate by cookie' , function () {
      var application = 'testApp32';
      var session = sessions.create(application);

      var httpHeaders = {
        cookie: 'bar=foo;foo=baz;QEWDTOKEN=' + session.token
      };

      var results = sessions.httpAuthenticate(httpHeaders);

      expect(results.error).toBeUndefined();
      expect(results.session).toBeDefined();
    });

    it('should authenticate by custom cookie' , function () {
      var application = 'testApp33';
      var session = sessions.create(application);

      var httpHeaders = {
        cookie: 'bar=foo;foo=baz;$bar$=' + session.token
      };
      var credentials = {
        cookie: '$bar$'
      };

      var results = sessions.httpAuthenticate(httpHeaders, credentials);

      expect(results.error).toBeUndefined();
      expect(results.session).toBeDefined();
    });

    it('should return missing authorization or cookie header', function () {
      var application = 'testApp34';
      sessions.create(application);

      var httpHeaders = {};
      var results = sessions.httpAuthenticate(httpHeaders);

      expect(results.error).toBe('Missing Authorization or Cookie Header');
      expect(results.status.code).toBe(403);
      expect(results.status.text).toBe('Forbidden');
    });

    it('should return missing or empty qewd session token', function () {
      var application = 'testApp35';
      sessions.create(application);

      var httpHeaders = {
        authorization: ''
      };
      var results = sessions.httpAuthenticate(httpHeaders);

      expect(results.error).toBe('Missing Authorization or Cookie Header');
      expect(results.status.code).toBe(403);
      expect(results.status.text).toBe('Forbidden');
    });
  });

  describe('#authenticateRestRequest', function () {
    it('should authenticate by token', function () {
      var application = 'testApp40';
      var session = sessions.create(application);

      var req = {
        headers: {
          authorization: session.token
        }
      };
      var finished = jasmine.createSpy();

      var results = sessions.authenticateRestRequest(req, finished, false, 'noCheck');

      expect(results).toBeTruthy();
      expect(req.session).toBeDefined();
      expect(finished).not.toHaveBeenCalled();
    });

    it('should authenticate by bearer', function () {
      var application = 'testApp41';
      var session = sessions.create(application);

      var req = {
        headers: {
          authorization: 'Bearer ' + session.token
        }
      };
      var finished = jasmine.createSpy();

      var results = sessions.authenticateRestRequest(req, finished, true, 'noCheck');

      expect(results).toBeTruthy();
      expect(req.session).toBeDefined();
      expect(finished).not.toHaveBeenCalled();
    });

    it('should finish with authorization header missing error', function () {
      var application = 'testApp42';
      sessions.create(application);

      var req = {
        headers: {}
      };
      var finished = jasmine.createSpy();
      var results = sessions.authenticateRestRequest(req, finished);

      expect(results).toBeFalsy();
      expect(req.session).toBeUndefined();
      expect(finished).toHaveBeenCalledWith({
        error: 'Authorization header missing'
      });
    });

    it('should finish with authorization header invalid  error', function () {
      var application = 'testApp42';
      sessions.create(application);

      var req = {
        headers: {
          authorization: 'Bearer'
        }
      };
      var finished = jasmine.createSpy();
      var results = sessions.authenticateRestRequest(req, finished, true);

      expect(results).toBeFalsy();
      expect(req.session).toBeUndefined();
      expect(finished).toHaveBeenCalledWith({
        error: 'Authorization header invalid - expected format: Bearer {{token}}'
      });
    });
  });

  describe('#active', function () {
    it('should return active sessions', function () {
      var application = 'testApp50';
      var session1 = sessions.create(application);
      var session2 = sessions.create(application);

      session2.expiryTime = new Date(2017, 0, 1).getTime() / 1000;

      var activeSessions = sessions.active();

      expect(activeSessions.length).toBe(1);
      expect(activeSessions[0].id).toBe(session1.id);
    });
  });

  describe('#byToken', function () {
    it('should return session by token', function () {
      var application = 'testApp60';
      var session = sessions.create(application);

      var actual = sessions.byToken(session.token);

      expect(actual.id).toBe(session.id);
    });
  });

  it('should be able to manage allowed serivices', function () {
    var application = 'testApp70';
    var session = sessions.create(application);

    session.allowService('service1');
    session.disallowService('service2');

    var actual = sessions.byToken(session.token);

    expect(actual.allowedServices).toEqual({
      service1: true,
      service2: false
    });
  });

  it('should be able to set/get ipAddress', function () {
    var application = 'testApp80';
    var session = sessions.create(application);

    session.ipAddress = '127.0.0.1';

    var actual = sessions.byToken(session.token);

    expect(actual.ipAddress).toBe('127.0.0.1');
  });

  describe('#garbageCollector', function () {
    beforeEach(function () {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 30000;
    });

    afterEach(function () {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 5000;
    });

    it('should clear expired sessions', function (done) {
      var q = new qoper8.masterProcess();
      var application = 'testApp90';

      sessions.create(application);

      var session2 = sessions.create(application);
      session2.expiryTime = new Date(2017, 0, 1).getTime() / 1000;

      q.on('start', function () {
        this.worker.loaderFilePath = process.cwd() +  '/node_modules/ewd-qoper8-worker.js';
        this.worker.module = process.cwd() +  '/spec/integration/fixtures/workerModule';
        this.exitOnStop = false;
      });

      q.on('started', function () {
        q.startWorker();
      });

      q.on('stop', function () {
        done();
      });

      q.start();

      setTimeout(function () {
        q.stop();
      }, 8000);
    });
  });
});
