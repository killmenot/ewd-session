'use strict';

var rewire = require('rewire');
var session = rewire('../../../../lib/proto/token/session');
var documentNodeMock = require('../../mocks/documentNode');
var documentStoreMock = require('../../mocks/documentStore');

describe('unit/proto/token/session:', function () {
  var Token;
  var SessionFactory;
  var Session;
  var token;
  var documentStore;
  var spy;

  var revert = function (obj) {
    obj.revert();
    delete obj.revert;
  };

  beforeAll(function () {
    SessionFactory = function () {
      return new Session();
    };

    Token = function (documentStore) {
      this.documentStore = documentStore;
      this.sessionId = '12345';
      this.documentName = 'ewdSession';
    };

    var proto = Token.prototype;
    Object.defineProperty(proto, 'session', session);
  });

  beforeEach(function () {
    documentStore = documentStoreMock.mock();

    token = new Token(documentStore);
    token.data = documentNodeMock.mock();

    spy = jasmine.createSpy().and.callFake(SessionFactory);
    spy.revert = session.__set__('Session', spy);
  });

  afterEach(function () {
    revert(spy);
  });

  it('should return false when non exist', function () {
    Session = function () {
      this.exists = false;
    };

    expect(token.session).toBeFalsy();
    expect(spy).toHaveBeenCalledWith(documentStore, '12345', false, 'ewdSession');
  });

  it('should return false when non expired', function () {
    Session = function () {
      this.expired = true;
      this.exists = true;
    };

    expect(token.session).toBeFalsy();
    expect(spy).toHaveBeenCalledWith(documentStore, '12345', false, 'ewdSession');
  });

  it('should return session', function () {
    var sessionInstance = {
      expired: false,
      exists: true
    };

    Session = function () {
      return sessionInstance;
    };

    expect(token.session).toBe(sessionInstance);
    expect(spy).toHaveBeenCalledWith(documentStore, '12345', false, 'ewdSession');
  });
});
