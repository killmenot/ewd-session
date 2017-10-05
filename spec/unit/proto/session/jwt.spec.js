'use strict';

var jwt = require('../../../../lib/proto/session/jwt');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/jwt:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {};

    var proto = Session.prototype;
    Object.defineProperty(proto, 'jwt', jwt);
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should return jwt value', function () {
    var expected = 'jwtValue';
    var node = {
      value: 'jwtValue'
    };
    session.data.$.and.returnValue(node);

    var actual = session.jwt;

    expect(actual).toBe(expected);
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'jwt', 'token']);
  });

  it('should set jwt value', function () {
    var expected = 'jwtValue';
    var node = {};
    session.data.$.and.returnValue(node);

    session.jwt = 'jwtValue';

    expect(node.value).toBe(expected);
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'jwt', 'token']);
  });
});
