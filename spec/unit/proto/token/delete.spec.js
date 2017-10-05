'use strict';

var deleteMethod = require('../../../../lib/proto/token/delete');
var documentNodeMock = require('../../mocks/documentNode');

describe('unit/proto/token/delete:', function () {
  var Token;
  var token;

  beforeAll(function () {
    Token = function () {
      this.delete = deleteMethod;
    };
  });

  beforeEach(function () {
    token = new Token();
    token.data = documentNodeMock.mock();
  });

  it('should delete document node', function () {
    token.delete();
    expect(token.data.delete).toHaveBeenCalled();
  });
});
