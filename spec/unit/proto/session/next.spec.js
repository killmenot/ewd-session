'use strict';

var next = require('../../../../lib/proto/session/next');
var documentStoreMock = require('../../mocks/documentStore');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/next:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {
      this.documentName = 'ewdSession';

      this.next = next;
    };
  });

  beforeEach(function () {
    session = new Session();
    session.documentStore = documentStoreMock.mock();
  });

  it('should return next session id', function () {
    var expected = '5';

    var node = documentNodeMock.mock();
    node.increment.and.returnValue(expected);
    spyOn(session.documentStore, 'DocumentNode').and.returnValue(node);

    var actual = session.next();

    expect(session.documentStore.DocumentNode).toHaveBeenCalledWith('ewdSession', ['sessionNo']);
    expect(node.increment).toHaveBeenCalled();
    expect(actual).toBe(expected);
  });
});
