'use strict';

var rewire = require('rewire');
var updateJWT = rewire('../../../../lib/proto/session/updateJWT');

describe('unit/proto/session/updateJWT:', function () {
  var Session;
  var session;
  var nowTime;
  var jwt;

  var revert = function (obj) {
    obj.revert();
    delete obj.revert;
  };

  beforeAll(function () {
    Session = function () {
      this.application = 'appValue';
      this.jwtSecret = 'jwtSecretValue';

      this.updateJWT = updateJWT;
    };
  });

  beforeEach(function () {
    jasmine.clock().install();

    nowTime = Date.UTC(2017, 0, 1); // 1483228800000, now
    jasmine.clock().mockDate(new Date(nowTime));

    session = new Session();
    session.expiryTime = nowTime / 1000 + 6 * 60 * 60; // 1483250400, 6 hours ahead

    jwt = jasmine.createSpyObj('jwt', ['decode', 'encode']);
    jwt.revert = updateJWT.__set__('jwt', jwt);
  });

  afterEach(function () {
    jasmine.clock().uninstall();

    revert(jwt);
  });

  it('should update jwt token', function () {
    var expected = 'updatedJwtToken';
    var newPayload = {
      foo: 'newValue',
      bar: 'barValue'
    };

    jwt.decode.and.returnValue({
      foo: 'oldValue',
      baz: 'bazValue',
      exp: nowTime / 1000 + 3 * 60 * 60, // 1483239600, 3 hours ahead
      iat: nowTime / 1000 - 1 * 60 * 60, // 1483225200, 1 hour behind
      iss: 'qewd:appValue',
      jti: 'tokenValue.1483225200'
    });

    jwt.encode.and.returnValue('updatedJwtToken');

    var actual = session.updateJWT(newPayload);

    expect(jwt.encode).toHaveBeenCalledWith({
      foo: 'newValue',
      baz: 'bazValue',
      exp: 1483250400,
      iat: 1483228800,
      iss: 'qewd:appValue',
      jti: 'tokenValue.1483228800',
      bar: 'barValue'
    }, 'jwtSecretValue');
    expect(session.jwt).toBe(expected);
    expect(actual).toBe(expected);
  });

  it('should update jwt token without newPayload', function () {
    var expected = 'updatedJwtToken';

    jwt.decode.and.returnValue({
      foo: 'oldValue',
      baz: 'bazValue',
      exp: nowTime / 1000 + 3 * 60 * 60, // 1483239600, 3 hours ahead
      iat: nowTime / 1000 - 1 * 60 * 60, // 1483225200, 1 hour behind
      iss: 'qewd:appValue',
      jti: 'tokenValue.1483225200'
    });

    jwt.encode.and.returnValue('updatedJwtToken');

    var actual = session.updateJWT();

    expect(jwt.encode).toHaveBeenCalledWith({
      foo: 'oldValue',
      baz: 'bazValue',
      exp: 1483250400,
      iat: 1483228800,
      iss: 'qewd:appValue',
      jti: 'tokenValue.1483228800'
    }, 'jwtSecretValue');
    expect(session.jwt).toBe(expected);
    expect(actual).toBe(expected);
  });
});
