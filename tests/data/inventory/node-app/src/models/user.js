const mongoose = require('mongoose');

// phone: String was dropped from the schema (comments must not count).
const userSchema = new mongoose.Schema({
  email: { type: String, required: true },
  fullName: String,
  passwordHash: String,
  dateOfBirth: Date,
  phoneNumber: String,
  lastLoginIp: String,
  theme: String,
});

module.exports = mongoose.model('User', userSchema);
