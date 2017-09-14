'use strict';

var updateExpiry = require('../../../../lib/proto/session/updateExpiry');

describe('unit/proto/session/updateExpiry:', function () {
  var Session;
  var session;
  var nowTime;

  beforeAll(function () {
    Session = function () {
      this.updateExpiry = updateExpiry;
    };
  });

  beforeEach(function () {
    jasmine.clock().install();

    nowTime = Date.UTC(2017, 0, 1); // 1483228800000, now
    jasmine.clock().mockDate(new Date(nowTime));

    session = new Session();
  });

  afterEach(function () {
    jasmine.clock().uninstall();
  });

  it('should do nothing when expired', function () {
    var expected = nowTime / 1000 - 1 * 60 * 60; // 1 hour behind

    session.expired = true;
    session.expiryTime = expected;

    session.updateExpiry();

    expect(session.expiryTime).toBe(expected);
  });

  it('should update expiryTime when non expired', function () {
    var expected = nowTime / 1000 + 3 * 60 * 60; // 3 hours ahead

    session.expired = false;
    session.timeout = 3 * 60 * 60;
    session.expiryTime = nowTime / 1000 + 1 * 60 * 60; // 1 hour ahead

    session.updateExpiry();

    expect(session.expiryTime).toBe(expected);
  });
});
