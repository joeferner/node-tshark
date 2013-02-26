'use strict';

var metrics = module.exports = {
};

metrics.Counter = function() {
  this.startTime = new Date();
  this.sum = 0;
};

metrics.Counter.prototype.update = function(val) {
  this.sum += val;
};

metrics.Counter.prototype.mean = function() {
  var dt = (new Date() - this.startTime) / 1000.0;
  return this.sum / dt;
};

metrics.Value = function() {
  this.min = Number.MAX_VALUE;
  this.max = Number.MIN_VALUE;
  this.value = 0;
  this.count = 0;
};

metrics.Value.prototype.update = function(val) {
  this.min = Math.min(val, this.min);
  this.max = Math.max(val, this.max);
  this.value = ((this.value * this.count) + val) / (this.count + 1);
  this.count++;
};

metrics.Value.prototype.mean = function() {
  return this.value;
};
