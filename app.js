const fs = require("fs");
const axios = require("axios");
const cheerio = require("cheerio");
const path = require("path");
const schedule = require("node-schedule");
require("dotenv").config({
  path: path.resolve(__dirname, "./.env"),
});
const { connectDB } = require("./Config/dbConfig");
const { cveUrl } = require("./Config/allDomains");
const { saveToDB } = require("./saveToDb");

let allCVEversions = "./scrapped/foo.json";
let allCVEinfo = "./scrapped/bar.json";

const {
  createTechVersionCVE,
  readTechVersionCVE,
  updateTechVersionCVE,
  createVulnInfoCVE,
  readVulnInfoCVE,
  updateVulnInfoCVE,
} = require("./services/vulnerbilitiesInfoService");

let int = 0;

let getAllVersionCveData = async (items) => {
  console.log(`Started scrapping for ${Object.keys(items).length} items`);
  let reArranageArr = [];
  for (service in items) {
    reArranageArr.push({
      [service]: items[service],
    });
  }
  let finalData = {};
  let allInfo = await Promise.all(
    reArranageArr.map(extractVersionAndCVEforIndividualService)
  );
  for (item of allInfo) {
    if (item) {
      let name = Object.keys(item)[0];
      let value = item[name];
      finalData = {
        ...finalData,
        [name]: value,
      };
    }
  }

  return finalData;
};

let extractVersionAndCVEforIndividualService = async (objOfServices) => {
  return new Promise(async (resolve, reject) => {
    console.log(`Scrapping started for ${Object.keys(objOfServices)[0]}`);
    // pack all into array of promises
    let service = Object.keys(objOfServices)[0];
    let urlOfService = objOfServices[service];
    let test1 = {};
    await axios
      .get(urlOfService, { parameter: { limit: 5000 } }, { timeout: 10000 })
      .then(async (resp) => {
        const $ = cheerio.load(resp.data);
        const page = $.root();
        let allPages = [];
        for (let i = 0; i < page.find("div.paging a").length; i++) {
          let url =
            "https://www.cvedetails.com" +
            page.find("div.paging a")[i].attribs.href;
          allPages.push(url);
        }

        for (let i = 0; i < allPages.length; i++) {
          await axios
            .get(allPages[i])
            .then(async (response) => {
              let $$ = cheerio.load(response.data);
              let page1 = $$.root();
              let tr = page1.find("table.listtable tr");
              // console.log(tr);
              for (elem of tr) {
                const loadTable = cheerio.load(elem);
                const allVersion = loadTable.root().find("tr");
                const vul = allVersion
                  .find("> :nth-child(6) a")
                  .next()
                  .attr("href");
                const version = allVersion
                  .find("> :nth-child(1)")
                  .text()
                  .trim();
                const vulNum = allVersion.find("td.num").text();
                if (vul !== undefined) {
                  if (Number(vulNum) !== 0) {
                    const loadVuln = await axios.get(
                      "https://www.cvedetails.com" + vul
                    );
                    const vuln = cheerio.load(loadVuln.data);
                    const allVuln = vuln.root().find("#contentdiv");
                    // const vulPage = allVuln.find("div.paging a").length;
                    const test = [];
                    let allVulnList = allVuln.find("tr.srrowns >:nth-child(2)");
                    allVulnList.each(function (i, elem) {
                      const loadVulnList = cheerio.load(elem);
                      const cve = loadVulnList.root().find("a").text();
                      if (cve.includes("CVE")) {
                        test.push(cve);
                      }
                    });
                    const json = {
                      [version]: test,
                    };
                    // console.log(test);
                    Object.assign(test1, json);
                  } else {
                    const json = {
                      [version]: null,
                    };
                    Object.assign(test1, json);
                  }
                }
              }
            })
            .catch((err) => {
              console.log(err);
            });
        }
        console.log("Scrapping for " + service);
        resolve({
          [service]: test1,
        });
      })
      .catch((err) => {
        console.log(err);
      });
  });
};

let getAllCVEinfo = async () => {
  return new Promise((resolve, reject) => {
    let file = {};
    let allCVE = [];
    fs.readFile(allCVEversions, async (err, data) => {
      if (err) {
        // console.log(err);
        throw err;
      } else {
        let json = JSON.parse(data);
        let allvalues = Object.values(json);

        // gathering all the
        for (let i = 0; i < allvalues.length; i++) {
          let allValues2 = Object.values(allvalues[i]);
          for (item of allValues2) {
            if (item !== null) {
              for (cve of item) {
                if (!allCVE.includes(cve)) {
                  allCVE.push(cve);
                }
              }
            }
          }
        }

        for (cve of allCVE) {
          // console.log(cve);
          await axios
            .get(`https://www.cvedetails.com/cve/${cve}`)
            .then(async (res) => {
              const mainUrl = cheerio.load(res.data);
              const detail = mainUrl.root().find("#cvedetails");
              let desc = detail.find("div.cvedetailssummary").text().trim();
              desc = desc.split("\t\n")[0];
              const cveScore = detail
                .find(
                  "table#cvssscorestable tbody >:nth-child(1) > :nth-child(2)"
                )
                .text()
                .trim();
              const cveType = detail
                .find(
                  "table#cvssscorestable tbody >:nth-child(8) > :nth-child(2)"
                )
                .text()
                .trim();
              let result = {
                [cve]: {
                  score: cveScore,
                  type: cveType,
                  desc: desc,
                },
              };
              let score =
                cveScore >= 7 ? "High" : cveScore < 4 ? "Low" : "Medium";
              const findCve = await readVulnInfoCVE({ cveid: cve });
              if (findCve) {
                await updateVulnInfoCVE(
                  { _id: findCve._id },
                  {
                    cveid: cve,
                    vulnerability_description: desc,
                    vulnerability_type: cveType,
                    vulnerability_severity: score,
                  }
                );
              } else {
                await createVulnInfoCVE({
                  cveid: cve,
                  vulnerability_description: desc,
                  vulnerability_type: cveType,
                  vulnerability_severity: score,
                  vulnerability_remediation:
                    "Update the tech to latest version.",
                  impact:
                    "Attackers can use publicly available exploits to exploit this vulnerability.",
                });
              }
              Object.assign(file, result);
            })
            .catch((err) => {
              console.log(err);
            });
        }
        resolve(file);
      }
    });
  });
};

let runner = async () => {
  // saving all versions and corrosponding
  let allData = await getAllVersionCveData(cveUrl);
  fs.writeFileSync("./scrapped/foo.json", JSON.stringify(allData), (err) => {
    if (err) throw err;
    console.log("Scrapped all tech-version-cves!");
  });

  // saving all cves
  let allDataOfCVE = await getAllCVEinfo();
  fs.writeFileSync(
    "./scrapped/bar.json",
    JSON.stringify(allDataOfCVE),
    (err) => {
      if (err) throw err;
      console.log("Scrapped all CVEs-info!");
    }
  );
};

try {
  const job = schedule.scheduleJob("01 42 09 * * *", async () => {
    console.log("Scraping started at " + new Date());
    await connectDB();
    await runner();
    await saveToDB();
    console.log("Scraping finished at " + new Date());
    int = int + 1;
    console.log("Total scraping " + int);
  });
  job;
} catch (error) {
  console.log(error);
}
