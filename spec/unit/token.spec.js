'use strict';

var rewire = require('rewire');
var Token = rewire('../../lib/token');
var documentStoreMock = require('./mocks/documentStore');
var documentNodeMock = require('./mocks/documentNode');

describe('unit/token:', function () {
  var documentStore;
  var uuid;

  var revert = function (obj) {
    obj.revert();
    delete obj.revert;
  };

  beforeEach(function () {
    documentStore = documentStoreMock.mock();

    uuid = jasmine.createSpy().and.returnValue('foo$bar$baz');
    uuid.revert = Token.__set__('uuid', uuid);
  });

  afterEach(function () {
    revert(uuid);
  });

  describe('constructor', function () {
    var tokenNode;
    var tokenGlobal;

    beforeEach(function () {
      tokenNode = documentNodeMock.mock();
      tokenGlobal = documentNodeMock.mock();
      tokenGlobal.$.and.returnValue(tokenNode);

      spyOn(documentStore, 'DocumentNode').and.returnValue(tokenGlobal);
    });

    it('defaults', function () {
      var token = new Token(documentStore);

      expect(token.documentName).toBe('%zewdSession');
      expect(token.documentStore).toBe(documentStore);
      expect(token.value).toBe('foo$bar$baz');
      expect(documentStore.DocumentNode).toHaveBeenCalledWith('%zewdSession', ['sessionsByToken']);
      expect(tokenGlobal.$).toHaveBeenCalledWith('foo$bar$baz');
      expect(token.data).toBe(tokenNode);
    });

    it('custom token', function () {
      var token = new Token(documentStore, 'tokenValue');

      expect(token.value).toBe('tokenValue');
      expect(tokenGlobal.$).toHaveBeenCalledWith('tokenValue');
    });

    it('custom document name', function () {
      var token = new Token(documentStore, 'tokenValue', 'foobar');

      expect(token.documentName).toBe('foobar');
      expect(documentStore.DocumentNode).toHaveBeenCalledWith('foobar', ['sessionsByToken']);
    });
  });

  describe('props', function () {
    [
      'session',
      'sessionId',
      'exists'
    ].forEach(function (prop) {
      it(prop, function () {
        var token = new Token(documentStore, 'tokenValue', 'ewdSession');
        var proto = Object.getPrototypeOf(token);
        var actual = Object.getOwnPropertyDescriptor(proto, prop);

        expect(actual).toBeDefined();
      });
    });
  });

  describe('methods', function () {
    [
      'delete'
    ].forEach(function (method) {
      it(method, function () {
        var token = new Token(documentStore, 'tokenValue', 'ewdSession');

        expect(token[method]).toEqual(jasmine.any(Function));
      });
    });
  });
});
