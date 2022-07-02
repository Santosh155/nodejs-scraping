const mongoose = require("mongoose");

const TechVersionCVE = new mongoose.Schema({
  tech: { type: String, required: true },
  version: { type: String, required: true },
  CVE: [String],
});

module.exports = mongoose.model("test_testversionsCVE", TechVersionCVE);
