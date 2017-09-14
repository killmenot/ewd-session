'use strict';

var expired = require('../../../../lib/proto/session/expired');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/session/expired:', function () {
  var Session;
  var session;
  var nowTime;

  beforeAll(function () {
    Session = function () {
      this.delete = jasmine.createSpy();
    };

    var proto = Session.prototype;
    Object.defineProperty(proto, 'expired', expired);
  });

  beforeEach(function () {
    jasmine.clock().install();

    nowTime = Date.UTC(2017, 0, 1); // 1483228800000, now
    jasmine.clock().mockDate(new Date(nowTime));

    session = new Session();
    session.data = documentNodeMock.mock();
  });

  afterEach(function () {
    jasmine.clock().uninstall();
  });

  it('should return true when non exists', function () {
    session.exists = false;
    expect(session.expired).toBeTruthy();
  });

  it('should return false when non expired', function () {
    session.exists = true;
    session.expiryTime = nowTime / 1000 + 1 * 60 * 60; // 1 hour ahead

    expect(session.expired).toBeFalsy();
  });

  it('should return true when expired', function () {
    session.exists = true;
    session.expiryTime = nowTime / 1000 - 1 * 60 * 60; // 1 hour behind

    var actual = session.expired;

    expect(session.delete).toHaveBeenCalled();
    expect(actual).toBeTruthy();
  });
});
