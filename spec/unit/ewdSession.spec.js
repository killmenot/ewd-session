'use strict';

var rewire = require('rewire');
var regexp = require('uuid-regexp/regexp');
var ewdSession = rewire('../../lib/ewdSession');
var documentStoreMock = require('./mocks/documentStore');

describe('unit/ewdSession:', function () {
  var documentStore;

  beforeEach(function () {
    documentStore = documentStoreMock.mock();
  });

  afterEach(function () {
    ewdSession.__set__('documentStore', undefined);
    ewdSession.__set__('documentName', undefined);
  });

  describe('#init', function () {
    it('should be function', function () {
      expect(ewdSession.init).toEqual(jasmine.any(Function));
    });

    it('should initialize module', function () {
      ewdSession.init(documentStore);

      expect(ewdSession.__get__('documentStore')).toBe(documentStore);
      expect(ewdSession.__get__('documentName')).toBe('%zewdSession');
    });

    it('should initialize module with custom document name', function () {
      ewdSession.init(documentStore, 'foobar');

      expect(ewdSession.__get__('documentStore')).toBe(documentStore);
      expect(ewdSession.__get__('documentName')).toBe('foobar');
    });
  });

  describe('#addTo', function () {
    it('should be function', function () {
      expect(ewdSession.addTo).toEqual(jasmine.any(Function));
    });

    it('should be reference to init method', function () {
      expect(ewdSession.addTo).toBe(ewdSession.init);
    });
  });

  describe('#create', function () {
    beforeEach(function () {
      ewdSession.init(documentStore);
    });

    it('should be function', function () {
      expect(ewdSession.create).toEqual(jasmine.any(Function));
    });
  });

  describe('#uuid', function () {
    it('should return uuid', function () {
      expect(ewdSession.uuid).toMatch(regexp.versioned.source);
    });
  });

  describe('#symbolTable', function () {
    it('should be function', function () {
      expect(ewdSession.symbolTable).toEqual(jasmine.any(Function));
    });
  });

  describe('#garbageCollector', function () {
    it('should be function', function () {
      expect(ewdSession.garbageCollector).toEqual(jasmine.any(Function));
    });
  });

  describe('#authenticate', function () {
    it('should be function', function () {
      expect(ewdSession.authenticate).toEqual(jasmine.any(Function));
    });
  });

  describe('#authenticateByJWT', function () {
    it('should be function', function () {
      expect(ewdSession.authenticateByJWT).toEqual(jasmine.any(Function));
    });
  });

  describe('#httpAuthenticate', function () {
    it('should be function', function () {
      expect(ewdSession.httpAuthenticate).toEqual(jasmine.any(Function));
    });
  });

  describe('#authenticateRestRequest', function () {
    it('should be function', function () {
      expect(ewdSession.authenticateRestRequest).toEqual(jasmine.any(Function));
    });
  });

  describe('#active', function () {
    it('should be function', function () {
      expect(ewdSession.active).toEqual(jasmine.any(Function));
    });
  });

  describe('#byToken', function () {
    it('should be function', function () {
      expect(ewdSession.byToken).toEqual(jasmine.any(Function));
    });
  });
});
