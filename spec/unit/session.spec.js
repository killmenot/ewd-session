'use strict';

var Session = require('../../lib/session');
var documentStoreMock = require('./mocks/documentStore');

describe('unit/session:', function () {
  var documentStore;

  beforeEach(function () {
    documentStore = documentStoreMock.mock();
  });

  describe('constructor', function () {
    it('defaults', function () {
      var session = new Session(documentStore, '12345', false);

      expect(session.documentName).toBe('%zewdSession');
      expect(session.documentStore).toBe(documentStore);
      expect(session.id).toBe('12345');
      expect(session.data instanceof session.documentStore.DocumentNode).toBeTruthy();
      expect(session.data.documentStore).toBe(documentStore);
      expect(session.data.documentName).toBe('%zewdSession');
      expect(session.data.path).toEqual(['session', '12345']);
    });

    it('custom document name', function () {
      var session = new Session(documentStore, '12345', false, 'foobar');

      expect(session.documentName).toBe('foobar');
      expect(session.data.documentName).toBe('foobar');
    });

    it('update expiry', function () {
      var spy = spyOn(Session.prototype, 'updateExpiry');

      var session = new Session(documentStore, '12345', true);

      expect(session).toBeDefined();
      expect(spy).toHaveBeenCalled();
    });

    it('generate session id', function () {
      var spy = spyOn(Session.prototype, 'next').and.returnValue('98765');

      var session = new Session(documentStore);

      expect(spy).toHaveBeenCalled();
      expect(session.id).toBe('98765');
      expect(session.data.path).toEqual(['session', '98765']);
    });
  });

  describe('props', function () {
    [
      'exists',
      'token',
      'expired',
      'authenticated',
      'expiryTime',
      'application',
      'timeout',
      'allowedServices',
      'socketId',
      'ipAddress',
      'jwt',
      'jwtSecret'
    ].forEach(function (prop) {
      it(prop, function () {
        var session = new Session(documentStore, '12345', false, 'ewdSession');
        var proto = Object.getPrototypeOf(session);
        var actual = Object.getOwnPropertyDescriptor(proto, prop);

        expect(actual).toBeDefined();
      });
    });
  });

  describe('methods', function () {
    [
      'next',
      'updateExpiry',
      'allowService',
      'disallowService',
      'sendToSocket',
      'createJWT',
      'updateJWT',
      'delete'
    ].forEach(function (method) {
      it(method, function () {
        var session = new Session(documentStore, '12345', false, 'ewdSession');

        expect(session[method]).toEqual(jasmine.any(Function));
      });
    });
  });
});
