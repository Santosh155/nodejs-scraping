const fs = require("fs");
let allCVEversions = "./scrapped/foo.json";

const {
  createTechVersionCVE,
  readTechVersionCVE,
  updateTechVersionCVE,
} = require("./services/vulnerbilitiesInfoService");

exports.saveToDB = async () => {
  // console.log("saving scrapped data to db");
  let readCveVersion = fs.readFileSync(allCVEversions, "utf8");
  readCveVersion = JSON.parse(readCveVersion);
  for (let i = 0; i < Object.keys(readCveVersion).length; i++) {
    const tech = Object.keys(readCveVersion)[i];
    const version = readCveVersion[tech];
    for (let j = 0; j < Object.keys(version).length; j++) {
      const versionNum = Object.keys(version)[j];
      const cveDetails = Object.values(version)[j];
      const findTech = await readTechVersionCVE({
        tech,
        version: versionNum,
      });
      if (findTech) {
        await updateTechVersionCVE(
          { _id: findTech._id },
          {
            CVE: cveDetails,
          }
        );
      } else {
        await createTechVersionCVE({
          tech: tech.toLocaleLowerCase(),
          version: versionNum ? versionNum : "0",
          CVE: cveDetails,
        });
      }
    }
  }
  // console.log("TechVersionCVE completed");
};
