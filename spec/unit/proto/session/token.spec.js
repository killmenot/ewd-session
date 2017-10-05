'use strict';

var token = require('../../../../lib/proto/session/token');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/token:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {};

    var proto = Session.prototype;
    Object.defineProperty(proto, 'token', token);
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should return token', function () {
    var expected = 'tokenValue';
    session.data.$.and.returnValue({
      value: 'tokenValue'
    });

    var actual = session.token;

    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'token']);
    expect(actual).toBe(expected);
  });
});
