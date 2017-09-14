'use strict';

var rewire = require('rewire');
var deleteMethod = rewire('../../../../lib/proto/session/delete');
var documentNodeMock = require('../../mocks/documentNode');
var documentStoreMock = require('../../mocks/documentStore');

describe('unit/proto/session/delete:', function () {
  var Session;
  var Token;
  var session;
  var spy;
  var documentStore;

  var revert = function (obj) {
    obj.revert();
    delete obj.revert;
  };

  beforeAll(function () {
    Token = function () {
      this.delete = jasmine.createSpy();
    };

    Session = function (documentStore) {
      this.documentStore = documentStore;
      this.token = 'tokenValue';
      this.documentName = 'ewdSession';

      this.delete = deleteMethod;
    };
  });

  beforeEach(function () {
    documentStore = documentStoreMock.mock();

    session = new Session(documentStore);
    session.data = documentNodeMock.mock();

    spy = jasmine.createSpy().and.callFake(Token);
    spy.revert = deleteMethod.__set__('Token', spy);
  });

  afterEach(function () {
    revert(spy);
  });

  it('should not set value', function () {
    session.delete();

    expect(spy).toHaveBeenCalledWith(documentStore, 'tokenValue', 'ewdSession');
    expect(session.data.delete).toHaveBeenCalled();
  });
});
