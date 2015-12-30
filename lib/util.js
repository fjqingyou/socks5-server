'use strict';

module.exports = {
  valueToKey: function(object, value) {
    for (var key in object) {
      if (value === object[key]) {
        return key;
      }
    }
    return value;
  }
};
