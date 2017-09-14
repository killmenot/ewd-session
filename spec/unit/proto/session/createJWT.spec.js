'use strict';

var rewire = require('rewire');
var createJWT = rewire('../../../../lib/proto/session/createJWT');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/createJWT:', function () {
  var Session;
  var session;
  var nowTime;
  var uuid;
  var jwt;

  var revert = function (obj) {
    obj.revert();
    delete obj.revert;
  };

  beforeAll(function () {
    Session = function () {
      this.application = 'appValue';
      this.token = 'tokenValue';

      this.createJWT = createJWT;
    };
  });

  beforeEach(function () {
    jasmine.clock().install();

    nowTime = Date.UTC(2017, 0, 1); // 1483228800000, now
    jasmine.clock().mockDate(new Date(nowTime));

    session = new Session();
    session.data = documentNodeMock.mock();
    session.expiryTime = nowTime / 1000 + 3 * 60 * 60; // 1483239600, 3 hours ahead

    jwt = jasmine.createSpyObj('jwt', ['encode']);
    uuid = jasmine.createSpy();

    jwt.revert = createJWT.__set__('jwt', jwt);
    uuid.revert = createJWT.__set__('uuid', uuid);
  });

  afterEach(function () {
    jasmine.clock().uninstall();

    revert(jwt);
    revert(uuid);
  });

  it('should return empty string', function () {
    var expected = '';

    var actual = session.createJWT();

    expect(actual).toBe(expected);
  });

  it('should create jwt token', function () {
    var expected = 'jwtTokenValue';
    var jwtPayload = {
      foo: 'bar'
    };

    var node = documentNodeMock.mock();
    session.data.$.and.returnValue(node);

    uuid.and.returnValue('jwtSecretValue');
    jwt.encode.and.returnValue('jwtTokenValue');

    var actual = session.createJWT(jwtPayload);

    expect(uuid).toHaveBeenCalled();
    expect(jwt.encode).toHaveBeenCalledWith({
      foo: 'bar',
      exp: 1483239600,
      iat: 1483228800,
      iss: 'qewd:appValue',
      jti: 'tokenValue.1483228800'
    }, 'jwtSecretValue');
    expect(session.data.$).toHaveBeenCalledWith(['ewd-session', 'jwt']);
    expect(node.setDocument).toHaveBeenCalledWith({
      secret: 'jwtSecretValue',
      token: 'jwtTokenValue'
    });
    expect(actual).toBe(expected);
  });
});
