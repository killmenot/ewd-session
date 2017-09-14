'use strict';

var jwtSecret = require('../../../../lib/proto/session/jwtSecret');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/jwtSecret:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {};

    var proto = Session.prototype;
    Object.defineProperty(proto, 'jwtSecret', jwtSecret);
  });

  beforeEach(function () {
    session = new Session();
    session.data = documentNodeMock.mock();
  });

  it('should return jwtSecret value', function () {
    var expected = 'jwtSecretValue';
    var node = {
      value: 'jwtSecretValue'
    };
    session.data.$.and.returnValue(node);

    var actual = session.jwtSecret;

    expect(actual).toBe(expected);
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'jwt', 'secret']);
  });

  it('should set jwtSecret value', function () {
    var expected = 'jwtSecretValue';
    var node = {};
    session.data.$.and.returnValue(node);

    session.jwtSecret = 'jwtSecretValue';

    expect(node.value).toBe(expected);
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'jwt', 'secret']);
  });
});
