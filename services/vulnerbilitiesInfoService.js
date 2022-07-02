const TechVersionCVE = require("../schema/TechVersionCVE");
const vulnerabilities_info_cve = require("../schema/vulnerabilities_info_cve");

exports.createTechVersionCVE = async (params) => {
  return await TechVersionCVE.create(params);
};

exports.readTechVersionCVE = async (filter = {}) => {
  return await TechVersionCVE.findOne(filter);
};

exports.updateTechVersionCVE = async (id, params) => {
  return await TechVersionCVE.updateOne(id, { ...params });
};

exports.createVulnInfoCVE = async (params) => {
  return await vulnerabilities_info_cve.create(params);
};

exports.readVulnInfoCVE = async (filter = {}) => {
  return await vulnerabilities_info_cve.findOne(filter);
};

exports.updateVulnInfoCVE = async (id, params) => {
  return await vulnerabilities_info_cve.updateOne(id, { ...params });
};
