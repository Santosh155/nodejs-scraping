const { Schema, model } = require("mongoose");

const vulnerabilities_info_cveScheme = new Schema({
  cveid: { type: String, unique: true },
  vulnerability_description: String,
  vulnerability_type: String,
  vulnerability_severity: String,
  vulnerability_remediation: String,
  vulnerability_refrences: String,
  impact: String,
});

module.exports = model(
  "test_vulnerabilities_info_cve",
  vulnerabilities_info_cveScheme
);
