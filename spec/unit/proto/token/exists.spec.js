'use strict';

var exists = require('../../../../lib/proto/token/exists');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/token/exists:', function () {
  var Token;
  var token;

  beforeAll(function () {
    Token = function () {};

    var proto = Token.prototype;
    Object.defineProperty(proto, 'exists', exists);
  });

  beforeEach(function () {
    token = new Token();
    token.data = documentNodeMock.mock();
  });

  it('should return document node existence value', function () {
    token.data.exists = true;
    expect(token.exists).toBeTruthy();
  });
});
