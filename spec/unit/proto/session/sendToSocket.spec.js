'use strict';

var sendToSocket = require('../../../../lib/proto/session/sendToSocket');

describe('unit/proto/session/sendToSocket:', function () {
  var Session;
  var session;

  beforeAll(function () {
    Session = function () {
      this.socketId = '/#yf_vd-S9Q7e-LX28AAAS';
      this.sendToSocket = sendToSocket;
    };

    process.send = jasmine.createSpy();
  });

  afterAll(function () {
    delete process.send;
  });

  beforeEach(function () {
    session = new Session();
  });

  it('should send to socket', function () {
    var type = 'foo';
    var message = {
      bar: 'baz'
    };

    session.sendToSocket(type, message);

    expect(process.send).toHaveBeenCalledWith({
      type: 'foo',
      finished: false,
      message: {
        bar: 'baz'
      },
      socketId: '/#yf_vd-S9Q7e-LX28AAAS'
    });
  });
});
